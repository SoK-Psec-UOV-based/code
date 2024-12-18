// SPDX-License-Identifier: Apache-2.0

#ifndef MAYO_H
#define MAYO_H

#define MAYO_VARIANT MAYO_1
#ifndef PQM4
#define PQM4
#endif

#include <stddef.h>
#include <stdint.h>

#define F_TAIL_LEN 5
#define F_TAIL_64                                                              \
  { 8, 0, 2, 8, 0 } // f(z) =  z^64         + x^3*z^3 + x*z^2         + x^3
#define F_TAIL_96                                                              \
  { 2, 2, 0, 2, 0 } // f(z) =  z^96         +   x*z^3         + x*z   + x
#define F_TAIL_128                                                             \
  { 4, 8, 0, 4, 2 } // f(z) = z^128 + x*z^4 + x^2*z^3         + x^3*z + x^2

#define MAYO_1_n 66
#define MAYO_1_m 64
#define MAYO_1_o 8
#define MAYO_1_v (MAYO_1_n - MAYO_1_o)
#define MAYO_1_A_cols (MAYO_1_k * MAYO_1_o + 1)
#define MAYO_1_k 9
#define MAYO_1_q 16
#define MAYO_1_m_bytes 32
#define MAYO_1_O_bytes 232
#define MAYO_1_v_bytes 29
#define MAYO_1_r_bytes 36
#define MAYO_1_P1_bytes 54752
#define MAYO_1_P2_bytes 14848
#define MAYO_1_P3_bytes 1152
#define MAYO_1_csk_bytes 24
#define MAYO_1_esk_bytes 69856
#define MAYO_1_cpk_bytes 1168
#define MAYO_1_epk_bytes 70752
#define MAYO_1_sig_bytes 321
#define MAYO_1_f_tail F_TAIL_64
#define MAYO_1_f_tail_arr f_tail_64
#define MAYO_1_salt_bytes 24
#define MAYO_1_digest_bytes 32
#define MAYO_1_pk_seed_bytes 16
#define MAYO_1_sk_seed_bytes 24

#define MAYO_2_n 78
#define MAYO_2_m 64
#define MAYO_2_o 18
#define MAYO_2_v (MAYO_2_n - MAYO_2_o)
#define MAYO_2_A_cols (MAYO_2_k * MAYO_2_o + 1)
#define MAYO_2_k 4
#define MAYO_2_q 16
#define MAYO_2_m_bytes 32
#define MAYO_2_O_bytes 540
#define MAYO_2_v_bytes 30
#define MAYO_2_r_bytes 36
#define MAYO_2_P1_bytes 58560
#define MAYO_2_P2_bytes 34560
#define MAYO_2_P3_bytes 5472
#define MAYO_2_csk_bytes 24
#define MAYO_2_esk_bytes 93684
#define MAYO_2_cpk_bytes 5488
#define MAYO_2_epk_bytes 98592
#define MAYO_2_sig_bytes 180
#define MAYO_2_f_tail F_TAIL_64
#define MAYO_2_f_tail_arr f_tail_64
#define MAYO_2_salt_bytes 24
#define MAYO_2_digest_bytes 32
#define MAYO_2_pk_seed_bytes 16
#define MAYO_2_sk_seed_bytes 24

#define MAYO_3_n 99
#define MAYO_3_m 96
#define MAYO_3_o 10
#define MAYO_3_v (MAYO_3_n - MAYO_3_o)
#define MAYO_3_A_cols (MAYO_3_k * MAYO_3_o + 1)
#define MAYO_3_k 11
#define MAYO_3_q 16
#define MAYO_3_m_bytes 48
#define MAYO_3_O_bytes 445
#define MAYO_3_v_bytes 45
#define MAYO_3_r_bytes 55
#define MAYO_3_P1_bytes 192240
#define MAYO_3_P2_bytes 42720
#define MAYO_3_P3_bytes 2640
#define MAYO_3_csk_bytes 32
#define MAYO_3_esk_bytes 235437
#define MAYO_3_cpk_bytes 2656
#define MAYO_3_epk_bytes 237600
#define MAYO_3_sig_bytes 577
#define MAYO_3_f_tail F_TAIL_96
#define MAYO_3_f_tail_arr f_tail_96
#define MAYO_3_salt_bytes 32
#define MAYO_3_digest_bytes 48
#define MAYO_3_pk_seed_bytes 16
#define MAYO_3_sk_seed_bytes 32

#define MAYO_5_n 133
#define MAYO_5_m 128
#define MAYO_5_o 12
#define MAYO_5_v (MAYO_5_n - MAYO_5_o)
#define MAYO_5_A_cols (MAYO_5_k * MAYO_5_o + 1)
#define MAYO_5_k 12
#define MAYO_5_q 16
#define MAYO_5_m_bytes 64
#define MAYO_5_O_bytes 726
#define MAYO_5_v_bytes 61
#define MAYO_5_r_bytes 72
#define MAYO_5_P1_bytes 472384
#define MAYO_5_P2_bytes 92928
#define MAYO_5_P3_bytes 4992
#define MAYO_5_csk_bytes 40
#define MAYO_5_esk_bytes 566078
#define MAYO_5_cpk_bytes 5008
#define MAYO_5_epk_bytes 570304
#define MAYO_5_sig_bytes 838
#define MAYO_5_f_tail F_TAIL_128
#define MAYO_5_f_tail_arr f_tail_128
#define MAYO_5_salt_bytes 40
#define MAYO_5_digest_bytes 64
#define MAYO_5_pk_seed_bytes 16
#define MAYO_5_sk_seed_bytes 40

#define PARAM_JOIN2_(a, b) a##_##b
#define PARAM_JOIN2(a, b) PARAM_JOIN2_(a, b)
#define PARAM_NAME(end) PARAM_JOIN2(MAYO_VARIANT, end)

#ifdef ENABLE_PARAMS_DYNAMIC
#define NAME_MAX mayo5
#define N_MAX 133
#define M_MAX 128
#define O_MAX 18
#define K_MAX 12
#define Q_MAX 16
#define PK_SEED_BYTES_MAX 16
#define SK_SEED_BYTES_MAX 40
#define SALT_BYTES_MAX 40
#define DIGEST_BYTES_MAX 64
#define O_BYTES_MAX 726
#define V_BYTES_MAX 61
#define R_BYTES_MAX 72
#define P1_BYTES_MAX 472384
#define P2_BYTES_MAX 92928
#define P3_BYTES_MAX 5472
#define SIG_BYTES_MAX 838
#define CPK_BYTES_MAX 5488
#define CSK_BYTES_MAX 40
#define ESK_BYTES_MAX 566078
#define EPK_BYTES_MAX 570304
#define N_MINUS_O_MAX 121
#define M_BYTES_MAX 64
#elif defined(MAYO_VARIANT)
#define M_MAX PARAM_NAME(m)
#define N_MAX PARAM_NAME(n)
#define O_MAX PARAM_NAME(o)
#define V_MAX PARAM_NAME(v)
#define K_MAX PARAM_NAME(k)
#define Q_MAX PARAM_NAME(q)
#define M_BYTES_MAX PARAM_NAME(m_bytes)
#define O_BYTES_MAX PARAM_NAME(O_bytes)
#define V_BYTES_MAX PARAM_NAME(v_bytes)
#define R_BYTES_MAX PARAM_NAME(r_bytes)
#define P1_BYTES_MAX PARAM_NAME(P1_bytes)
#define P2_BYTES_MAX PARAM_NAME(P2_bytes)
#define P3_BYTES_MAX PARAM_NAME(P3_bytes)
#define CSK_BYTES_MAX PARAM_NAME(csk_bytes)
#define ESK_BYTES_MAX PARAM_NAME(esk_bytes)
#define CPK_BYTES_MAX PARAM_NAME(cpk_bytes)
#define EPK_BYTES_MAX PARAM_NAME(epk_bytes)
#define N_MINUS_O_MAX (N_MAX - O_MAX)
#define SALT_BYTES_MAX PARAM_NAME(salt_bytes)
#define DIGEST_BYTES_MAX PARAM_NAME(digest_bytes)
#define PK_SEED_BYTES_MAX PARAM_NAME(pk_seed_bytes)
#define SK_SEED_BYTES_MAX SALT_BYTES_MAX
#else
#error "Parameter not specified"
#endif

/**
 * Struct defining MAYO parameters
 */
typedef struct {
    int m;
    int n;
    int o;
    int k;
    int q;
    const unsigned char *f_tail;
    int m_bytes;
    int O_bytes;
    int v_bytes;
    int r_bytes;
    int R_bytes;
    int P1_bytes;
    int P2_bytes;
    int P3_bytes;
    int csk_bytes;
    int esk_bytes;
    int cpk_bytes;
    int epk_bytes;
    int sig_bytes;
    int salt_bytes;
    int sk_seed_bytes;
    int digest_bytes;
    int pk_seed_bytes;
    const char *name;
} mayo_params_t;

typedef struct sk_t {
    uint8_t o[O_BYTES_MAX];
    uint32_t p[P1_BYTES_MAX/4 + P2_BYTES_MAX/4];
} sk_t;

/**
 * MAYO parameter sets
 */
extern const mayo_params_t MAYO_1;
extern const mayo_params_t MAYO_2;
extern const mayo_params_t MAYO_3;
extern const mayo_params_t MAYO_5;

/**
 * Status codes
 */
#define MAYO_OK 0
#define MAYO_ERR 1

/**
 * Mayo keypair generation.
 *
 * The implementation corresponds to Mayo.CompactKeyGen() in the Mayo spec.
 * The caller is responsible to allocate sufficient memory to hold pk and sk.
 *
 * @param[in] p Mayo parameter set
 * @param[out] pk Mayo public key
 * @param[out] sk Mayo secret key
 * @return int status code
 */
int mayo_keypair(const mayo_params_t *p, unsigned char *pk, unsigned char *sk);

/**
 * MAYO signature generation.
 *
 * The implementation performs Mayo.expandSK() + Mayo.sign() in the Mayo spec.
 * Keys provided is a compacted secret keys.
 * The caller is responsible to allocate sufficient memory to hold sm.
 *
 * @param[in] p Mayo parameter set
 * @param[out] sm Signature concatenated with message
 * @param[out] smlen Pointer to the length of sm
 * @param[in] m Message to be signed
 * @param[in] mlen Message length
 * @param[in] sk Compacted secret key
 * @return int status code
 */
int mayo_sign(const mayo_params_t *p, unsigned char *sm,
              unsigned long long *smlen, const unsigned char *m,
              unsigned long long mlen, const unsigned char *sk);

/**
 * Mayo open signature.
 *
 * The implementation performs Mayo.verify(). If the signature verification succeeded, the original message is stored in m.
 * Keys provided is a compact public key.
 * The caller is responsible to allocate sufficient memory to hold m.
 *
 * @param[in] p Mayo parameter set
 * @param[out] m Message stored if verification succeeds
 * @param[out] mlen Pointer to the length of m
 * @param[in] sm Signature concatenated with message
 * @param[in] smlen Length of sm
 * @param[in] pk Compacted public key
 * @return int status code
 */
int mayo_open(const mayo_params_t *p, unsigned char *m,
              unsigned long long *mlen, const unsigned char *sm,
              unsigned long long smlen, const unsigned char *pk);

/**
 * Mayo compact keypair generation.
 *
 * The implementation corresponds to Mayo.CompactKeyGen() in the Mayo spec.
 * The caller is responsible to allocate sufficient memory to hold pk and sk.
 * 
 * outputs a pair (csk, cpk) \in B^{csk_bytes} x B^{cpk_bytes}, where csk and
 * cpk are compact representations of a Mayo secret key and public key
 *
 * @param[in] p Mayo parameter set
 * @param[out] cpk Mayo compacted public key
 * @param[out] csk Mayo compacted secret key
 * @return int status code
 */
int mayo_keypair_compact(const mayo_params_t *p, unsigned char *cpk,
                         unsigned char *csk);

/**
 * Mayo expand public key.
 *
 * The implementation corresponds to Mayo.expandPK() in the Mayo spec.
 * The caller is responsible to allocate sufficient memory to hold epk.
 *
 * @param[in] p Mayo parameter set
 * @param[in] cpk Compacted public key.
 * @param[out] epk Expanded public key.
 * @return int return code
 */
int mayo_expand_pk(const mayo_params_t *p, const unsigned char *cpk,
                   unsigned char *epk);

/**
 * Mayo expand secret key.
 *
 * The implementation corresponds to Mayo.expandSK() in the Mayo spec.
 * The caller is responsible to allocate sufficient memory to hold esk.
 *
 * @param[in] p Mayo parameter set
 * @param[in] csk Compacted secret key.
 * @param[out] esk Expanded secret key.
 * @return int return code
 */
int mayo_expand_sk(const mayo_params_t *p, const unsigned char *csk,
                   sk_t *esk);

/**
 * Mayo verify signature.
 *
 * The implementation performs Mayo.verify(). If the signature verification succeeded, returns 0, otherwise 1.
 * Keys provided is a compact public key.
 *
 * @param[in] p Mayo parameter set
 * @param[out] m Message stored if verification succeeds
 * @param[out] mlen Pointer to the length of m
 * @param[in] sig Signature
 * @param[in] siglen Length of sig
 * @param[in] pk Compacted public key
 * @return int 0 if verification succeeded, 1 otherwise.
 */
int mayo_verify(const mayo_params_t *p, const unsigned char *m,
                unsigned long long mlen, const unsigned char *sig,
                  const unsigned char *pk);

#endif