AES GCM SIV

In the following package 2 different packages included:

1. AES GCM SIV Package - ASM code - performance code.
2. AES GENEREL PURPOSE GCM SIV - C code - works on any computer.

Both of the codes were validated and both supply same output. 
The Performance code has more details on output.

Each package contains EXEC Files to run, sample output file,
result of measurements (Performance package).

Each exec file has 2 inputs <AAD_LEN> <MSG LEN> and same input "constants" 
as sample - so it will be easy to verify and check with each other.

Please read each README for further details.

Results on performance code:
                1 KEY DEC                                           2 KEY DEC	
                HSW [C/B]    BDW [C/B]   SKL [C/B]                	HSW [C/B]   BDW [C/B]    SKL [C/B]
AAD=0 MSG=1024  1.53        1.06        0.88        AAD=0 MSG=1024	1.47        1.00        0.83
AAD=0 MSG=2048  1.35        0.88        0.73        AAD=0 MSG=2048	1.30        0.85        0.71
AAD=0 MSG=4096  1.29        0.82        0.69        AAD=0 MSG=4096	1.27        0.81        0.68
AAD=0 MSG=8192  1.25        0.78        0.65        AAD=0 MSG=8192	1.23        0.77        0.65
AAD=0 MSG=16384	1.24        0.76        0.65        AAD=0 MSG=16384	1.22        0.76        0.64
								
								
                1 KEY ENC                                           2 KEY ENC	
                HSW [C/B]   BDW [C/B]   SKL [C/B]                   HSW [C/B]   BDW [C/B]   SKL [C/B]
AAD=0 MSG=1024  1.63        1.25        1.19        AAD=0 MSG=1024	1.50        1.16        1.11
AAD=0 MSG=2048  1.43        1.07        1.06        AAD=0 MSG=2048	1.37        1.03        1.02
AAD=0 MSG=4096  1.34        0.98        0.99        AAD=0 MSG=4096	1.30        0.96        0.97
AAD=0 MSG=8192  1.29        0.94        0.96        AAD=0 MSG=8192	1.27        0.93        0.95
AAD=0 MSG=16384 1.26        0.92        0.94        AAD=0 MSG=16384	1.26        0.91        0.94
