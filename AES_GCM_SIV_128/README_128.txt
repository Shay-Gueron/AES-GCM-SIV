AES GCM SIV

In the following package 3 different packages included:

1. AES GCM SIV Package - ASM code - performance code - this versions was tested on linux based systems.
2. AES GENEREL PURPOSE GCM SIV - C code - works on any computer.
3. AES GCM SIV Package MAC OS- ASM code - performance code - version enabled for MAC OS using xcode, llvm and gcc.
   The tested machine is using Apple LLVM Version 7.3.0 (clang-703.0.29) with target x86_64-apple-darwin15.3.0.

Both of the codes were validated and both supply same output. 
The Performance code has more details on output.

Each package contains EXEC Files to run, sample output file,
result of measurements (Performance package).

Each exec file has 2 inputs <AAD_LEN> <MSG LEN> and same input "constants" 
as sample - so it will be easy to verify and check with each other.

Please read each README for further details.

Results on performance code:
                2 KEY DEC	
              	HSW [C/B]   BDW [C/B]    SKL [C/B]
AAD=0 MSG=1024	1.47        1.00        0.83
AAD=0 MSG=2048	1.30        0.85        0.71
AAD=0 MSG=4096	1.27        0.81        0.68
AAD=0 MSG=8192	1.23        0.77        0.65
AAD=0 MSG=16384	1.22        0.76        0.64


                2 KEY ENC	
                HSW [C/B]   BDW [C/B]   SKL [C/B]
AAD=0 MSG=1024	1.50        1.16        1.11
AAD=0 MSG=2048	1.37        1.03        1.02
AAD=0 MSG=4096	1.30        0.96        0.97
AAD=0 MSG=8192	1.27        0.93        0.95
AAD=0 MSG=16384	1.26        0.91        0.94
