#include "masked.h"
#include "fips202.h"
#include "fips202-masked.h"

#if defined(STM32F2) || defined(STM32F4) || defined(STM32L4R5ZI) && !defined(MPS2_AN386)

#include <libopencm3/stm32/rng.h>

//TODO Maybe we do not want to use the hardware RNG for all randomness, but instead only read a seed and then expand that using fips202.

int randombytes_no_zero(uint8_t *obuf, size_t len)
{
    union
    {
        unsigned char aschar[4];
        uint32_t asint;
    } random;

    while (len > 4)
    {
        random.asint = rng_get_random_blocking();
        if(random.aschar[0] != 0) {
            *obuf++ = random.aschar[0];
            len -= 1;
        }
        if(random.aschar[1] != 0) {
            *obuf++ = random.aschar[1];
            len -= 1;
        }      
        if(random.aschar[2] != 0) {
            *obuf++ = random.aschar[2];
            len -= 1;
        }          
        if(random.aschar[3] != 0) {
            *obuf++ = random.aschar[3];
            len -= 1;
        }               
        // *obuf++ = random.aschar[1];
        // *obuf++ = random.aschar[2];
        // *obuf++ = random.aschar[3];
        // len -= 4;
    }
    if (len > 0)
    {
        for (random.asint = rng_get_random_blocking(); len > 0;)
        {
            if(random.aschar[len - 1] != 0) {
                *obuf++ = random.aschar[len - 1];
                len -= 1;
            }
        }
    }

    return 0;
}

#endif


void masked_hash_g_len(masked_vinegar *out, const int outlen, const uint8_t *in, const int inlen) {
    #if MASKING_N != 2
        #error "Keccak only available for MASKING_N=2"
    #endif

    shake256_masked_inlen(out->share[0].u8, out->share[1].u8, outlen, in, in + inlen, inlen);
}