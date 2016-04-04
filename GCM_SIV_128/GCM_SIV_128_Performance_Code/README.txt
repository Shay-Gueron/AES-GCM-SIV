To compile, use the makefile in 2 ways:
1. make DEF=-DDETAILS -DLITTLE_ENDIAN_   - If printouts needed
2. make DEF=-DCOUNT	     - If measurement needed    
3. make DEF=-DCOUNT -DADD_INFO	     - If measurement needed + additional info
4. make DEF=-DCOUNT -DADD_INFO	     - If measurement needed + additional info
By default printouts are made.


The executables receive 2 parameters
The parameters are: GCM_SIV_1_KEY_ENC A B
A - AAD length in bytes
B - MSG length in bytes
