#ifndef _GCM_SIV_Ref_H
#define _GCM_SIV_Ref_H

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#if !defined (ALIGN16)
#if defined (__GNUC__)
#  define ALIGN16  __attribute__  ( (aligned (16)))
# else
#  define ALIGN16 __declspec (align (16))
# endif
#endif

void GCM_SIV_ENC_2_Keys(uint8_t* CT, 				// Output
						uint8_t TAG[16], 			// Output
						uint8_t K1[32],
						uint8_t N[16],
						uint8_t* AAD,
						uint8_t* MSG,
						uint64_t AAD_len,
						uint64_t MSG_len);

int GCM_SIV_DEC_2_Keys(uint8_t* MSG, 				// Output
						uint8_t TAG[16],
						uint8_t K1[32],
						uint8_t N[16],
						uint8_t* AAD,
						uint8_t* CT,
						uint64_t AAD_len,
						uint64_t CT_len);

#endif /* _GCM_SIV_Ref_H */