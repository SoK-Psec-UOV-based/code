#ifndef MASKED_H
#define MASKED_H

#include "params.h"
#include <stdint.h>
#include <stddef.h>

#ifndef MASKING_N
#define MASKING_N 2
#endif /* MASKING_N */

// typedef struct {
//   uint8_t u8[LEN_SKSEED];
// } u8_seedbytes;

// typedef struct {
//   u8_seedbytes share[MASKING_N];
// } masked_sk_seed;

typedef struct {
  uint8_t u8[_PK_P2_BYTE];
} u8_Lbytes;

// typedef struct {
//   u8_Lbytes share[MASKING_N];
// } masked_L;

// buffer with the same size as L
typedef struct {
  u8_Lbytes share;
} masked_buffer;

// typedef struct {
//   uint8_t u8[64];
// } u8_64;

// typedef struct {
//   u8_64 share[MASKING_N];
// } masked_u8_64;

typedef struct {
  uint8_t u8[_V_BYTE];
} u8_vinegarbytes;

typedef struct {
  u8_vinegarbytes share[MASKING_N];
} masked_vinegar;

// typedef struct {
//   uint8_t u8[_V_BYTE*_O];
// } u8_t1bytes;

// typedef struct {
//   u8_t1bytes share[MASKING_N];
// } masked_t1;

// typedef struct {
//   uint8_t u8[_PK_P1_BYTE];
// } u8_P1bytes;

// typedef struct {
//   u8_P1bytes share[MASKING_N];
// } masked_P1;

// typedef struct {
//   uint8_t u8[_O_BYTE];
// } u8_oilbytes;

// typedef struct {
//   u8_oilbytes share[MASKING_N];
// } masked_oil;

// typedef struct {
//     // unsigned char sk_seed[LEN_SKSEED];   ///< seed for generating secret key
//     masked_sk_seed sk_seed;

//     // unsigned char t1[_V_BYTE*_O];   ///< T map
//     masked_t1 t1;

//     unsigned char P1[_PK_P1_BYTE];  ///< part of C-map, P1

//     // unsigned char L[_PK_P2_BYTE];                 ///< part of C-map, L
//     masked_L L;

// } masked_sk_t;

// void masked_hash_g(masked_u8_64 *out, const masked_u8_64 *in);

// void masked_hash_g_len(masked_vinegar *out, const masked_u8_64 *in, const int len);

void masked_hash_g_len(masked_vinegar *out, const int outlen, const uint8_t *in, const int inlen);

int randombytes_no_zero(uint8_t *output, size_t n);

#endif /* MASKED_H */