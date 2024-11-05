#ifndef MASKED_H
#define MASKED_H

#include "mayo.h"
#include <stdint.h>

#ifndef MASKING_N
#define MASKING_N 2
#endif /* MASKING_N */


typedef struct {
  unsigned char u8[PK_SEED_BYTES_MAX + O_BYTES_MAX];
} S_bytes;

typedef struct {
  S_bytes share[MASKING_N];
} masked_S;

typedef struct {
  unsigned char u8[PK_SEED_BYTES_MAX];
} seed_pk_bytes;

typedef struct {
  seed_pk_bytes share[MASKING_N];
} masked_seed_pk;


typedef struct {
  unsigned char u8[(N_MINUS_O_MAX)*O_MAX];
} O_bytes;

typedef struct {
  O_bytes share[MASKING_N];
} masked_O;

typedef struct {
  unsigned char u8[DIGEST_BYTES_MAX + SALT_BYTES_MAX + SK_SEED_BYTES_MAX + 1];
} tmp_bytes;

typedef struct {
  tmp_bytes share[MASKING_N];
} masked_tmp;

typedef struct {
  unsigned char u8[CSK_BYTES_MAX];
} csk_bytes;

typedef struct {
  csk_bytes share[MASKING_N];
} masked_csk;

typedef struct {
  uint32_t u32[P1_BYTES_MAX/4 + P2_BYTES_MAX/4];
} P_bytes;

typedef struct {
  P_bytes share[MASKING_N];
} masked_P;

typedef struct {
  uint8_t u8[O_BYTES_MAX];
} O_enc_bytes;

typedef struct {
  O_enc_bytes share[MASKING_N];
} masked_enc_O;

typedef struct {
    masked_enc_O O;
    masked_P P;
} masked_sk_t;

typedef struct {
  uint8_t u8[K_MAX * V_BYTES_MAX + R_BYTES_MAX];
} V_bytes;

typedef struct {
  V_bytes share[MASKING_N];
} masked_V;

typedef struct {
  uint8_t u8[N_MINUS_O_MAX * K_MAX];
} Vdec_bytes;

typedef struct {
  Vdec_bytes share[MASKING_N];
} masked_Vdec;

typedef struct {
  uint8_t u8[SK_SEED_BYTES_MAX];
} sk_seed_bytes;

typedef struct {
  sk_seed_bytes share[MASKING_N];
} masked_sk_seed;

typedef struct {
  uint8_t u8[SALT_BYTES_MAX];
} salt_bytes;

typedef struct {
  salt_bytes share[MASKING_N];
} masked_salt;

int masked_mayo_expand_sk(const mayo_params_t *p, const unsigned char *csk, masked_sk_t *sk);

void masked_hash_g_len(uint8_t *out, const int outlen, const uint8_t *in, const int inlen);

#endif /* MASKED_H */