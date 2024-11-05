#include "masked.h"
#include "fips202.h"
#include "fips202-masked.h"

void masked_hash_g_len(uint8_t *out, const int outlen, const uint8_t *in, const int inlen) {
    #if MASKING_N != 2
        #error "Keccak only available for MASKING_N=2"
    #endif

    shake256_masked_inlen(out, out + outlen, outlen, in, in + inlen, inlen);
}