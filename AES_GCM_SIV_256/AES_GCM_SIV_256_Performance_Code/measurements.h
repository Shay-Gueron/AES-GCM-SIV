/*
###############################################################################
# AES-GCM-SIV developers and authors:                                         #
#                                                                             #
# Shay Gueron,    University of Haifa, Israel and                             #
#                 Intel Corporation, Israel Development Center, Haifa, Israel #
# Adam Langley,   Google                                                      #
# Yehuda Lindell, Bar Ilan University                                         #
###############################################################################
#                                                                             #
# References:                                                                 #
#                                                                             #
# [1] S. Gueron, Y. Lindell, GCM-SIV: Full Nonce Misuse-Resistant             #
# Authenticated Encryption at Under One Cycle per Byte,                       #
# 22nd ACM Conference on Computer and Communications Security,                #
# 22nd ACM CCS: pages 109-119, 2015.                                          #
# [2] S. Gueron, A. Langley, Y. Lindell, AES-GCM-SIV: Nonce Misuse-Resistant  #
# Authenticated Encryption.                                                   #
# https://tools.ietf.org/html/draft-gueron-gcmsiv-02#                         #
###############################################################################
#                                                                             #
###############################################################################
#                                                                             #
# Copyright (c) 2016, Shay Gueron                                             #
#                                                                             #
#                                                                             #
# Permission to use this code for AES-GCM-SIV is granted.                     #
#                                                                             #
# Redistribution and use in source and binary forms, with or without          #
# modification, are permitted provided that the following conditions are      #
# met:                                                                        #
#                                                                             #
# * Redistributions of source code must retain the above copyright notice,    #
#   this list of conditions and the following disclaimer.                     #
#                                                                             #
# * Redistributions in binary form must reproduce the above copyright         #
#   notice, this list of conditions and the following disclaimer in the       #
#   documentation and/or other materials provided with the distribution.      #
#                                                                             #
# * The names of the contributors may not be used to endorse or promote       #
# products derived from this software without specific prior written          #
# permission.                                                                 #
#                                                                             #
###############################################################################
#                                                                             #
###############################################################################
# THIS SOFTWARE IS PROVIDED BY THE AUTHORS ""AS IS"" AND ANY                  #
# EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE           #
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR          #
# PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL INTEL CORPORATION OR              #
# CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,       #
# EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,         #
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR          #
# PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF      #
# LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING        #
# NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS          #
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.                #
###############################################################################
*/

#ifndef MEASURE_H
#define MEASURE_H

#ifndef RDTSC
#define MEASURE(x) (x)
#endif


/* This part defines the functions and MACROS needed to measure using RDTSC */
#ifdef RDTSC
   
   #ifndef REPEAT     
      #define REPEAT 500
   #endif
   
   #ifndef OUTER_REPEAT
      #define OUTER_REPEAT 30
   #endif

   #ifndef WARMUP
      #define WARMUP REPEAT/4
   #endif

    unsigned long long RDTSC_start_clk, RDTSC_end_clk;
    double RDTSC_total_clk;
    double RDTSC_TEMP_CLK;
    int RDTSC_MEASURE_ITERATOR;
    int RDTSC_OUTER_ITERATOR;

inline static unsigned long get_Clks(void)
{
    unsigned hi, lo;
    __asm__ __volatile__ ("rdtscp\n\t" : "=a"(lo), "=d"(hi)::"rcx");
    return ( (unsigned long)lo)^( ((unsigned long)hi)<<32 );
}

   /* 
   This MACRO measures the number of cycles "x" runs. This is the flow:
      1) it sets the priority to FIFO, to avoid time slicing if possible.
      2) it repeats "x" WARMUP times, in order to warm the cache.
      3) it reads the Time Stamp Counter at the beginning of the test.
      4) it repeats "x" REPEAT number of times.
      5) it reads the Time Stamp Counter again at the end of the test
      6) it calculates the average number of cycles per one iteration of "x", by calculating the total number of cycles, and dividing it by REPEAT
    */      
   #define RDTSC_MEASURE(x)                                                                         \
   for(RDTSC_MEASURE_ITERATOR=0; RDTSC_MEASURE_ITERATOR< WARMUP; RDTSC_MEASURE_ITERATOR++)          \
      {                                                                                             \
         {x};                                                                                       \
      }                                                                                    		    \
	RDTSC_total_clk = 1.7976931348623157e+308;                                                      \
	for(RDTSC_OUTER_ITERATOR=0;RDTSC_OUTER_ITERATOR<OUTER_REPEAT; RDTSC_OUTER_ITERATOR++){          \
      RDTSC_start_clk = get_Clks();                                                                 \
      for (RDTSC_MEASURE_ITERATOR = 0; RDTSC_MEASURE_ITERATOR < REPEAT; RDTSC_MEASURE_ITERATOR++)   \
      {                                                                                             \
         {x};                                                                                       \
      }                                                                                             \
      RDTSC_end_clk = get_Clks();                                                                   \
      RDTSC_TEMP_CLK = (double)(RDTSC_end_clk-RDTSC_start_clk)/REPEAT;                              \
		if(RDTSC_total_clk>RDTSC_TEMP_CLK) RDTSC_total_clk = RDTSC_TEMP_CLK;				        \
	}

   
    #define MEASURE(x) RDTSC_MEASURE(x)
  

#endif

#endif
