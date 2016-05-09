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
AAD=0 MSG=1024	1.98        1.49        1.19
AAD=0 MSG=2048	1.68        1.20        1.02
AAD=0 MSG=4096	1.54        1.13        0.96
AAD=0 MSG=8192	1.48        1.07        0.92
AAD=0 MSG=16384	1.45        1.04        0.90


                2 KEY ENC	
                HSW [C/B]   BDW [C/B]   SKL [C/B]
AAD=0 MSG=1024	1.90        1.60        1.53
AAD=0 MSG=2048	1.71        1.37        1.32
AAD=0 MSG=4096	1.61        1.26        1.25
AAD=0 MSG=8192	1.56        1.20        1.22
AAD=0 MSG=16384	1.54        1.17        1.20
