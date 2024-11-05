// SPDX-License-Identifier: Apache-2.0

#include <mem.h>
#include <mayo.h>
#include <rng.h>
#include <aes_ctr.h>
#include <bitsliced_arithmetic.h>
#include <simple_arithmetic.h>
#include <fips202.h>
#include <stdlib.h>
#include <string.h>
#include <stdalign.h>
#include "masked.h"
#ifdef ENABLE_CT_TESTING
#include <valgrind/memcheck.h>
#endif

#include <stdio.h>
#include "hal.h"
#include "sendfn.h"

#define PK_PRF AES_128_CTR
#define TICTOC
#include <debug_bench_tools.h>

// #define _BENCH_
#if defined(_BENCH_)
    #include "hal.h"
    #include "sendfn.h"
    #define printcycles(S, U) send_unsignedll((S), (U))
#endif

static void decode(const unsigned char *m, unsigned char *mdec, int mdeclen)
{
    int i;
    for (i = 0; i < mdeclen / 2; ++i)
    {
        *mdec++ = m[i] & 0xf;
        *mdec++ = m[i] >> 4;
    }

    if (mdeclen % 2 == 1)
    {
        *mdec++ = m[i] & 0x0f;
    }
}

static void encode(const unsigned char *m, unsigned char *menc, int mlen)
{
    int i;
    for (i = 0; i < mlen / 2; ++i, m += 2)
    {
        menc[i] = (*m) | (*(m + 1) << 4);
    }

    if (mlen % 2 == 1)
    {
        menc[i] = (*m);
    }
}

static void reduce_y_mod_fX(unsigned char *y, int m, int k,
                            const unsigned char *ftail)
{
    for (int i = m + k * (k + 1) / 2 - 2; i >= m; i--)
    {
        for (int j = 0; j < F_TAIL_LEN; j++)
        {
            y[i - m + j] ^= mul_f(y[i], ftail[j]);
        }
        y[i] = 0;
    }
}

static void reduce_A_mod_fX(unsigned char *A, int m, int k, int A_cols,
                            const unsigned char *ftail)
{
    for (int i = m + k * (k + 1) / 2 - 2; i >= m; i--)
    {
        for (int kk = 0; kk < A_cols - 1; kk++)
        {
            for (int j = 0; j < F_TAIL_LEN; j++)
            {
                A[(i - m + j) * A_cols + kk] ^= mul_f(A[i * A_cols + kk], ftail[j]);
            }
            A[i * A_cols + kk] = 0;
        }
    }
}

#define MAYO_POSITION_IN_UPPER_TRIAGONAL_MATRIX(i, j, size) \
    (i * size + j - (i * (i + 1) / 2))

// Public API

int mayo_keypair(const mayo_params_t *p, unsigned char *pk, unsigned char *sk)
{
    int ret = 0;

    ret = mayo_keypair_compact(p, pk, sk);
    if (ret != MAYO_OK)
    {
        goto err;
    }

err:
    return ret;
}

int mayo_sign(const mayo_params_t *p, unsigned char *sm,
                     unsigned long long *smlen, const unsigned char *m,
                     unsigned long long mlen, const unsigned char *csk)
{
    int ret = MAYO_OK;
    unsigned char tenc[M_BYTES_MAX], t[M_MAX]; // no secret data
    unsigned char y[2 * M_MAX] = {
        0};                             // 2*m entries to allow for lazy reduction mod f(X) // no secret data
    unsigned char salt[SALT_BYTES_MAX]; // not secret data
    // unsigned char V[K_MAX * V_BYTES_MAX + R_BYTES_MAX],
    //          Vdec[N_MINUS_O_MAX * K_MAX];              // secret data
    unsigned char M[M_MAX * O_MAX * K_MAX] = {0}; // secret data
    unsigned char A[2 * M_MAX * (K_MAX * O_MAX + 1)] = {
        0}; // make room for 2m rows to allow for lazy reduction mod f(X) //
    // secret data
    unsigned char x[K_MAX * N_MAX];           // not secret data
    unsigned char r[K_MAX * O_MAX + 1] = {0}; // secret data
    unsigned char s[K_MAX * N_MAX] = {0};     // not secret data
    const unsigned char *seed_sk;
    // unsigned char O[(N_MINUS_O_MAX)*O_MAX]; // secret data
    // alignas(32) sk_t sk; // secret data

    unsigned char Ox[N_MINUS_O_MAX]; // secret data
    // unsigned char Mdigest[DIGEST_BYTES];    char outword[P1_BYTES_MAX/4 + P2_BYTES_MAX/4];
    // unsigned char tmp[DIGEST_BYTES_MAX + SALT_BYTES_MAX + SK_SEED_BYTES_MAX + 1];
    unsigned char *ctrbyte;
    unsigned char *vi;
    unsigned char *Mi, *Mj;

    const int param_m = PARAM_m(p);
    const int param_n = PARAM_n(p);
    const int param_o = PARAM_o(p);
    const int param_k = PARAM_k(p);
    const int param_m_bytes = PARAM_m_bytes(p);
    const int param_v_bytes = PARAM_v_bytes(p);
    // const int param_O_bytes = PARAM_O_bytes(p);
    const int param_r_bytes = PARAM_r_bytes(p);
    const int param_P1_bytes = PARAM_P1_bytes(p);
    // const int param_P2_bytes = PARAM_P2_bytes(p);
    const int param_sig_bytes = PARAM_sig_bytes(p);
    const int param_A_cols = PARAM_A_cols(p);
    const int param_digest_bytes = PARAM_digest_bytes(p);
    const int param_sk_seed_bytes = PARAM_sk_seed_bytes(p);
    const int param_salt_bytes = PARAM_salt_bytes(p);

    masked_sk_t m_sk;
    masked_V m_V;
    masked_Vdec m_Vdec;
    masked_O m_O;

#if defined(_BENCH_)
    unsigned long long t0, t1;  
#endif    

    // unsigned char testV[N_MINUS_O_MAX * K_MAX];

    // masked_salt m_salt;
    unsigned char m_y[2 * M_MAX] = {0};
    unsigned char m_r[K_MAX * O_MAX + 1] = {0}; // secret data
    unsigned char tmp[(DIGEST_BYTES_MAX + SALT_BYTES_MAX + SK_SEED_BYTES_MAX) * 2];
    unsigned char *m_tmp = tmp + DIGEST_BYTES_MAX + SALT_BYTES_MAX + SK_SEED_BYTES_MAX;
    unsigned char m_x[K_MAX * N_MAX];
    unsigned char m_M[M_MAX * O_MAX * K_MAX] = {0}; // secret data
    unsigned char m_Ox[N_MINUS_O_MAX];

    seed_sk = csk;
    ret = masked_mayo_expand_sk(p, csk, &m_sk);
    if (ret != MAYO_OK)
    {
        goto err;
    }

    masked_sk_seed m_csk;
    randombytes(m_csk.share[1].u8, param_sk_seed_bytes);

    for (int i = 0; i < param_sk_seed_bytes; i++)
    {
        m_csk.share[0].u8[i] = m_csk.share[1].u8[i] ^ seed_sk[i];
    }

    decode(m_sk.O.share[0].u8, m_O.share[0].u8, (param_n - param_o) * param_o);
    decode(m_sk.O.share[1].u8, m_O.share[1].u8, (param_n - param_o) * param_o);

    // hash message
    shake256(tmp, param_digest_bytes, m, mlen);
    memcpy(m_tmp, tmp, param_digest_bytes);

    uint32_t *bitsliced_P1 = m_sk.P.share[0].u32;
    uint32_t *bitsliced_L = bitsliced_P1 + (param_P1_bytes / 4);
    uint32_t bitsliced_M[K_MAX * O_MAX * M_MAX / 8] = {0};

    uint32_t *m_bitsliced_P1 = m_sk.P.share[1].u32;
    uint32_t *m_bitsliced_L = m_bitsliced_P1 + (param_P1_bytes / 4);
    uint32_t m_bitsliced_M[K_MAX * O_MAX * M_MAX / 8] = {0};

#ifdef TARGET_BIG_ENDIAN
    for (int i = 0; i < param_P1_bytes / 4; ++i)
    {
        bitsliced_P1[i] = BSWAP32(bitsliced_P1[i]);
    }
    for (int i = 0; i < param_P2_bytes / 4; ++i)
    {
        bitsliced_L[i] = BSWAP32(bitsliced_L[i]);
    }
    for (int i = 0; i < param_P1_bytes / 4; ++i)
    {
        m_bitsliced_P1[i] = BSWAP32(m_bitsliced_P1[i]);
    }
    for (int i = 0; i < param_P2_bytes / 4; ++i)
    {
        m_bitsliced_L[i] = BSWAP32(m_bitsliced_L[i]);
    }
#endif

    // choose the randomizer
    if (randombytes(tmp + param_digest_bytes, param_salt_bytes) != MAYO_OK)
    {
        ret = MAYO_ERR;
        goto err;
    }

    // reuse salt bytes when masking
    memcpy(m_tmp + param_digest_bytes, tmp + param_digest_bytes, param_salt_bytes);

    // hashing to salt
    memcpy(tmp + param_digest_bytes + param_salt_bytes, seed_sk,
           param_sk_seed_bytes);

    shake256(salt, param_salt_bytes, tmp,
             param_digest_bytes + param_salt_bytes + param_sk_seed_bytes);
    

#ifdef ENABLE_CT_TESTING
    VALGRIND_MAKE_MEM_DEFINED(salt, SALT_BYTES_MAX); // Salt is not secret
#endif

    // hashing to t
    memcpy(tmp + param_digest_bytes, salt, param_salt_bytes);
    memcpy(m_tmp + param_digest_bytes, salt, param_salt_bytes);
    ctrbyte = tmp + param_digest_bytes + param_salt_bytes + param_sk_seed_bytes;

    shake256(tenc, param_m_bytes, tmp, param_digest_bytes + param_salt_bytes);
    decode(tenc, t, param_m); // may not be necessary
   

    memcpy(tmp + param_digest_bytes + param_salt_bytes, m_csk.share[0].u8,
           param_sk_seed_bytes);

    memcpy(m_tmp + param_digest_bytes + param_salt_bytes, m_csk.share[1].u8,
           param_sk_seed_bytes);

    for (int ctr = 0; ctr <= 255; ++ctr)
    {
        *ctrbyte = (unsigned char)ctr;
#if defined(_BENCH_) 
        t0 = hal_get_time();
        masked_hash_g_len((uint8_t *)&m_V, param_k * param_v_bytes + param_r_bytes, tmp, param_digest_bytes + param_salt_bytes + param_sk_seed_bytes + 1);
        t1 = hal_get_time();
        printcycles("BENCH 2 :", t1-t0);         
#else
        masked_hash_g_len((uint8_t *)&m_V, param_k * param_v_bytes + param_r_bytes, tmp, param_digest_bytes + param_salt_bytes + param_sk_seed_bytes + 1);
#endif
        // decode the v_i vectors
        for (int i = 0; i <= param_k - 1; ++i)
        {
            decode(m_V.share[0].u8 + i * param_v_bytes, m_Vdec.share[0].u8 + i * (param_n - param_o),
                   param_n - param_o);
            decode(m_V.share[1].u8 + i * param_v_bytes, m_Vdec.share[1].u8 + i * (param_n - param_o),
                   param_n - param_o);
        }
#if defined(_BENCH_) 
        t0 = hal_get_time();
        // compute all the v_i^T * L matrices.
        // v0*L0
        mul_add_mat_x_bitsliced_m_mat(param_m / 32, m_Vdec.share[0].u8, bitsliced_L, bitsliced_M, param_k, param_n - param_o, param_o);
        // v1*L0
        mul_add_mat_x_bitsliced_m_mat(param_m / 32, m_Vdec.share[1].u8, bitsliced_L, bitsliced_M, param_k, param_n - param_o, param_o);

        // v0*L1
        mul_add_mat_x_bitsliced_m_mat(param_m / 32, m_Vdec.share[0].u8, m_bitsliced_L, m_bitsliced_M, param_k, param_n - param_o, param_o);

        // v1*L1
        mul_add_mat_x_bitsliced_m_mat(param_m / 32, m_Vdec.share[1].u8, m_bitsliced_L, m_bitsliced_M, param_k, param_n - param_o, param_o);
        


        // move the Mi from bitsliced to "standard" representation
        for (int i = 0; i < param_k; i++)
        {
            Mi = M + i * param_m * param_o;
            // unbitslice Mi one column at a time
            unsigned char temp_Mi_col[M_MAX];
            for (int j = 0; j < param_o; j++)
            {
                unbitslice_m_vec(param_m / 32,
                                 bitsliced_M + (param_m / 8) * (i * param_o + j),
                                 temp_Mi_col);
                for (int k = 0; k < param_m; k++)
                {
                    *(Mi + k * param_o + j) = temp_Mi_col[k];
                }
            }
        }

        for (int i = 0; i < param_k; i++)
        {
            Mi = m_M + i * param_m * param_o;
            // unbitslice Mi one column at a time
            unsigned char temp_Mi_col[M_MAX];
            for (int j = 0; j < param_o; j++)
            {
                unbitslice_m_vec(param_m / 32,
                                 m_bitsliced_M + (param_m / 8) * (i * param_o + j),
                                 temp_Mi_col);
                for (int k = 0; k < param_m; k++)
                {
                    *(Mi + k * param_o + j) = temp_Mi_col[k];
                }
            }
        }

        for (int i = 0; i < M_MAX * O_MAX * K_MAX; i++)
        {
            M[i] = M[i] ^ m_M[i];
        }
        t1 = hal_get_time();
        printcycles("BENCH 3 :", t1-t0); 
#else
        // compute all the v_i^T * L matrices.
        // v0*L0
        mul_add_mat_x_bitsliced_m_mat(param_m / 32, m_Vdec.share[0].u8, bitsliced_L, bitsliced_M, param_k, param_n - param_o, param_o);
        // v1*L0
        mul_add_mat_x_bitsliced_m_mat(param_m / 32, m_Vdec.share[1].u8, bitsliced_L, bitsliced_M, param_k, param_n - param_o, param_o);

        // v0*L1
        mul_add_mat_x_bitsliced_m_mat(param_m / 32, m_Vdec.share[0].u8, m_bitsliced_L, m_bitsliced_M, param_k, param_n - param_o, param_o);

        // v1*L1
        mul_add_mat_x_bitsliced_m_mat(param_m / 32, m_Vdec.share[1].u8, m_bitsliced_L, m_bitsliced_M, param_k, param_n - param_o, param_o);
        


        // move the Mi from bitsliced to "standard" representation
        for (int i = 0; i < param_k; i++)
        {
            Mi = M + i * param_m * param_o;
            // unbitslice Mi one column at a time
            unsigned char temp_Mi_col[M_MAX];
            for (int j = 0; j < param_o; j++)
            {
                unbitslice_m_vec(param_m / 32,
                                 bitsliced_M + (param_m / 8) * (i * param_o + j),
                                 temp_Mi_col);
                for (int k = 0; k < param_m; k++)
                {
                    *(Mi + k * param_o + j) = temp_Mi_col[k];
                }
            }
        }

        for (int i = 0; i < param_k; i++)
        {
            Mi = m_M + i * param_m * param_o;
            // unbitslice Mi one column at a time
            unsigned char temp_Mi_col[M_MAX];
            for (int j = 0; j < param_o; j++)
            {
                unbitslice_m_vec(param_m / 32,
                                 m_bitsliced_M + (param_m / 8) * (i * param_o + j),
                                 temp_Mi_col);
                for (int k = 0; k < param_m; k++)
                {
                    *(Mi + k * param_o + j) = temp_Mi_col[k];
                }
            }
        }

        for (int i = 0; i < M_MAX * O_MAX * K_MAX; i++)
        {
            M[i] = M[i] ^ m_M[i];
        }
#endif


        memset(A, 0, 2 * param_m * param_A_cols);
        memcpy(y, t, param_m);

        // compute all the v_i^t * P^(1) * v_j
        alignas(32) uint32_t bitsliced_Pv[N_MINUS_O_MAX * K_MAX * M_MAX / 8] = {0};
        alignas(32) uint32_t bitsliced_vPv[K_MAX * K_MAX * M_MAX / 8] = {0};

        alignas(32) uint32_t m_bitsliced_Pv[N_MINUS_O_MAX * K_MAX * M_MAX / 8] = {0};
        alignas(32) uint32_t m_bitsliced_vPv[K_MAX * K_MAX * M_MAX / 8] = {0};

        for (int i = 0; i < N_MINUS_O_MAX * K_MAX; i++)
        {
            m_Vdec.share[0].u8[i] = m_Vdec.share[1].u8[i] ^ m_Vdec.share[0].u8[i];
        }

#if defined(_BENCH_) 
        t0 = hal_get_time();
        P1_times_Vt(p, bitsliced_P1, m_Vdec.share[0].u8, bitsliced_Pv);
        P1_times_Vt(p, m_bitsliced_P1, m_Vdec.share[0].u8, m_bitsliced_Pv);

        // 2x -> bitsliced_vPv
        mul_add_mat_x_bitsliced_m_mat(param_m / 32, m_Vdec.share[0].u8, bitsliced_Pv,
                                      bitsliced_vPv, param_k, param_n - param_o,
                                      param_k);

        mul_add_mat_x_bitsliced_m_mat(param_m / 32, m_Vdec.share[0].u8, m_bitsliced_Pv,
                                      m_bitsliced_vPv, param_k, param_n - param_o,
                                      param_k);

        alignas(32) uint32_t bitsliced_vPv_upper[K_MAX * (K_MAX + 1) / 2 * M_MAX / 8];
        alignas(32) uint32_t m_bitsliced_vPv_upper[K_MAX * (K_MAX + 1) / 2 * M_MAX / 8];

        bitsliced_m_upper(param_m / 32, bitsliced_vPv, bitsliced_vPv_upper,
                          param_k);
        bitsliced_m_upper(param_m / 32, m_bitsliced_vPv, m_bitsliced_vPv_upper,
                          param_k);
        
        int l = 0;
        for (int i = 0; i <= param_k - 1; ++i)
        {
            for (int j = param_k - 1; j >= i; --j)
            {
                int pos = MAYO_POSITION_IN_UPPER_TRIAGONAL_MATRIX(i, j, param_k);
                // unbitslice the vPV and subtract from to y, shifted "down" by l
                // positions
                unsigned char temp_y[M_MAX];
                // 2x
                unbitslice_m_vec(param_m / 32,
                                 bitsliced_vPv_upper + pos * (param_m / 8), temp_y);
                for (int k = 0; k < param_m; k++)
                {
                    y[l + k] ^= temp_y[k];
                }

                unbitslice_m_vec(param_m / 32,
                                 m_bitsliced_vPv_upper + pos * (param_m / 8), temp_y);
                for (int k = 0; k < param_m; k++)
                {
                    m_y[l + k] ^= temp_y[k];
                }

                // add the M_i and M_j to A, shifted "down" by l positions
                Mj = M + j * param_m * param_o;
                for (int rr = 0; rr < param_m; rr++)
                {
                    for (int c = 0; c < param_o; c++)
                    {
                        A[(rr + l) * param_A_cols + i * param_o + c] ^= Mj[rr * param_o + c];
                    }
                }

                if (i != j)
                {
                    Mi = M + i * param_m * param_o;
                    for (int rr = 0; rr < param_m; rr++)
                    {
                        for (int c = 0; c < param_o; c++)
                        {
                            A[(rr + l) * param_A_cols + j * param_o + c] ^=
                                Mi[rr * param_o + c];
                        }
                    }
                }
                l++;
            }
        }
        t1 = hal_get_time();
        printcycles("BENCH 4 :", t1-t0); 
#else
        P1_times_Vt(p, bitsliced_P1, m_Vdec.share[0].u8, bitsliced_Pv);
        P1_times_Vt(p, m_bitsliced_P1, m_Vdec.share[0].u8, m_bitsliced_Pv);

        // 2x -> bitsliced_vPv
        mul_add_mat_x_bitsliced_m_mat(param_m / 32, m_Vdec.share[0].u8, bitsliced_Pv,
                                      bitsliced_vPv, param_k, param_n - param_o,
                                      param_k);

        mul_add_mat_x_bitsliced_m_mat(param_m / 32, m_Vdec.share[0].u8, m_bitsliced_Pv,
                                      m_bitsliced_vPv, param_k, param_n - param_o,
                                      param_k);

        alignas(32) uint32_t bitsliced_vPv_upper[K_MAX * (K_MAX + 1) / 2 * M_MAX / 8];
        alignas(32) uint32_t m_bitsliced_vPv_upper[K_MAX * (K_MAX + 1) / 2 * M_MAX / 8];

        bitsliced_m_upper(param_m / 32, bitsliced_vPv, bitsliced_vPv_upper,
                          param_k);
        bitsliced_m_upper(param_m / 32, m_bitsliced_vPv, m_bitsliced_vPv_upper,
                          param_k);
        
        int l = 0;
        for (int i = 0; i <= param_k - 1; ++i)
        {
            for (int j = param_k - 1; j >= i; --j)
            {
                int pos = MAYO_POSITION_IN_UPPER_TRIAGONAL_MATRIX(i, j, param_k);
                // unbitslice the vPV and subtract from to y, shifted "down" by l
                // positions
                unsigned char temp_y[M_MAX];
                // 2x
                unbitslice_m_vec(param_m / 32,
                                 bitsliced_vPv_upper + pos * (param_m / 8), temp_y);
                for (int k = 0; k < param_m; k++)
                {
                    y[l + k] ^= temp_y[k];
                }

                unbitslice_m_vec(param_m / 32,
                                 m_bitsliced_vPv_upper + pos * (param_m / 8), temp_y);
                for (int k = 0; k < param_m; k++)
                {
                    m_y[l + k] ^= temp_y[k];
                }

                // add the M_i and M_j to A, shifted "down" by l positions
                Mj = M + j * param_m * param_o;
                for (int rr = 0; rr < param_m; rr++)
                {
                    for (int c = 0; c < param_o; c++)
                    {
                        A[(rr + l) * param_A_cols + i * param_o + c] ^= Mj[rr * param_o + c];
                    }
                }

                if (i != j)
                {
                    Mi = M + i * param_m * param_o;
                    for (int rr = 0; rr < param_m; rr++)
                    {
                        for (int c = 0; c < param_o; c++)
                        {
                            A[(rr + l) * param_A_cols + j * param_o + c] ^=
                                Mi[rr * param_o + c];
                        }
                    }
                }
                l++;
            }
        }    
#endif

        // reduce y and A mod f(X)
        reduce_y_mod_fX(y, param_m, param_k, PARAM_f_tail(p));
        reduce_y_mod_fX(m_y, param_m, param_k, PARAM_f_tail(p));

        reduce_A_mod_fX(A, param_m, param_k, param_A_cols, PARAM_f_tail(p));


        unsigned char m_A[2 * M_MAX * (K_MAX * O_MAX + 1)] = {
            0};
        memcpy(m_A, A, 2 * M_MAX * (K_MAX * O_MAX + 1));

#if defined(_BENCH_) 
        t0 = hal_get_time();    
        decode(m_V.share[0].u8 + param_k * param_v_bytes, r, param_k * param_o);
        decode(m_V.share[1].u8 + param_k * param_v_bytes, m_r, param_k * param_o);

        if (sample_solution(p, A, y, r, x, param_k, param_o, param_m, param_A_cols))
        {
            if (sample_solution(p, m_A, m_y, m_r, m_x, param_k, param_o, param_m, param_A_cols))
            {
                for (int i = 0; i < K_MAX * N_MAX; i++)
                {
                    x[i] = m_x[i] ^ x[i];
                }
            }
            break;
        }
        else
        {
            memset(bitsliced_M, 0, param_k * param_o * param_m / 8 * sizeof(uint32_t));
            memset(m_bitsliced_M, 0, param_k * param_o * param_m / 8 * sizeof(uint32_t));
        }       
#else
        decode(m_V.share[0].u8 + param_k * param_v_bytes, r, param_k * param_o);
        decode(m_V.share[1].u8 + param_k * param_v_bytes, m_r, param_k * param_o);

        if (sample_solution(p, A, y, r, x, param_k, param_o, param_m, param_A_cols))
        {
            if (sample_solution(p, m_A, m_y, m_r, m_x, param_k, param_o, param_m, param_A_cols))
            {
                for (int i = 0; i < K_MAX * N_MAX; i++)
                {
                    x[i] = m_x[i] ^ x[i];
                }
            }
            break;
        }
        else
        {
            memset(bitsliced_M, 0, param_k * param_o * param_m / 8 * sizeof(uint32_t));
            memset(m_bitsliced_M, 0, param_k * param_o * param_m / 8 * sizeof(uint32_t));
        }
#endif
    }
    
#if defined(_BENCH_) 
    t1 = hal_get_time();
    printcycles("BENCH 5 :", t1-t0); 
    t0 = hal_get_time(); 
    // s is already 0
    for (int i = 0; i <= param_k - 1; ++i)
    {
        vi = m_Vdec.share[0].u8 + i * (param_n - param_o);

        mat_mul(m_O.share[0].u8, x + i * param_o, Ox, param_o, param_n - param_o, 1);
        mat_mul(m_O.share[1].u8, x + i * param_o, m_Ox, param_o, param_n - param_o, 1);

        uint8_t m_vi[param_n - param_o];

        memset(m_vi, 0, param_n - param_o);
        mat_add(vi, Ox, m_vi, param_n - param_o, 1);
        mat_add(m_vi, m_Ox, s + i * param_n, param_n - param_o, 1);

        memcpy(s + i * param_n + (param_n - param_o), x + i * param_o, param_o);
    }
    t1 = hal_get_time();
    printcycles("BENCH 6 :", t1-t0);        
#else
    // s is already 0
    for (int i = 0; i <= param_k - 1; ++i)
    {
        vi = m_Vdec.share[0].u8 + i * (param_n - param_o);

        mat_mul(m_O.share[0].u8, x + i * param_o, Ox, param_o, param_n - param_o, 1);
        mat_mul(m_O.share[1].u8, x + i * param_o, m_Ox, param_o, param_n - param_o, 1);

        uint8_t m_vi[param_n - param_o];

        memset(m_vi, 0, param_n - param_o);
        mat_add(vi, Ox, m_vi, param_n - param_o, 1);
        mat_add(m_vi, m_Ox, s + i * param_n, param_n - param_o, 1);

        memcpy(s + i * param_n + (param_n - param_o), x + i * param_o, param_o);
    }    
#endif

    encode(s, sm, param_n * param_k);
    memcpy(sm + param_sig_bytes - param_salt_bytes, salt, param_salt_bytes);
    memmove(sm + param_sig_bytes, m,
            mlen); // assert: smlen == param_k * param_n + mlen
    *smlen = param_sig_bytes + mlen;
    
    return 0;    

err:
    mayo_secure_clear(m_V.share[0].u8, K_MAX * V_BYTES_MAX + R_BYTES_MAX);
    mayo_secure_clear(m_Vdec.share[0].u8, N_MINUS_O_MAX * K_MAX);
    mayo_secure_clear(M, M_MAX * O_MAX * K_MAX);
    mayo_secure_clear(A, 2 * M_MAX * (K_MAX * O_MAX + 1));
    mayo_secure_clear(r, K_MAX * O_MAX + 1);
    mayo_secure_clear(&m_O, (N_MINUS_O_MAX)*O_MAX*2);
    mayo_secure_clear(&m_sk, sizeof(masked_sk_t));
    mayo_secure_clear(Ox, N_MINUS_O_MAX);
    mayo_secure_clear(m_Ox, N_MINUS_O_MAX);    
    mayo_secure_clear(tmp,
                      DIGEST_BYTES_MAX + SALT_BYTES_MAX + SK_SEED_BYTES_MAX + 1);
    return ret;
}

int mayo_open(const mayo_params_t *p, unsigned char *m,
              unsigned long long *mlen, const unsigned char *sm,
              unsigned long long smlen, const unsigned char *pk)
{
    const int param_sig_bytes = PARAM_sig_bytes(p);
    if (smlen < (unsigned long long)param_sig_bytes)
    {
        return MAYO_ERR;
    }
    int result = mayo_verify(p, sm + param_sig_bytes, smlen - param_sig_bytes, sm,
                             pk);

    if (result == MAYO_OK)
    {
        *mlen = smlen - param_sig_bytes;
        memmove(m, sm + param_sig_bytes, *mlen);
    }

    return result;
}

int mayo_keypair_compact(const mayo_params_t *p, unsigned char *cpk,
                         unsigned char *csk)
{
    int ret = MAYO_OK;
    unsigned char *seed_sk = csk;
    unsigned char S[PK_SEED_BYTES_MAX + O_BYTES_MAX];
    alignas(32) uint32_t bitsliced_P[(P1_BYTES_MAX + P2_BYTES_MAX) / 4];
    alignas(32) uint32_t bitsliced_P3[O_MAX * O_MAX * M_MAX / 8] = {0};
    alignas(32) uint32_t bitsliced_P3_upper[P3_BYTES_MAX / 4];
    unsigned char *seed_pk;
    unsigned char O[(N_MINUS_O_MAX)*O_MAX];

    const int param_m = PARAM_m(p);
    const int param_v = PARAM_v(p);
    const int param_o = PARAM_o(p);
    const int param_O_bytes = PARAM_O_bytes(p);
    const int param_P1_bytes = PARAM_P1_bytes(p);
    const int param_P2_bytes = PARAM_P2_bytes(p);
    const int param_P3_bytes = PARAM_P3_bytes(p);
    const int param_pk_seed_bytes = PARAM_pk_seed_bytes(p);
    const int param_sk_seed_bytes = PARAM_sk_seed_bytes(p);

    // seed_sk $←- B^(sk_seed bytes)
    if (randombytes(seed_sk, param_sk_seed_bytes) != MAYO_OK)
    {
        ret = MAYO_ERR;
        goto err;
    }

    // S ← shake256(seedsk, pk seed bytes + O bytes)
    shake256(S, param_pk_seed_bytes + param_O_bytes, seed_sk,
             param_sk_seed_bytes);
    // seed_pk ← s[0 : pk_seed_bytes]
    seed_pk = S;

    // o ← Decode_o(s[pk_seed_bytes : pk_seed_bytes + o_bytes])
    decode(S + param_pk_seed_bytes, O, param_v * param_o);

#ifdef ENABLE_CT_TESTING
    VALGRIND_MAKE_MEM_DEFINED(seed_pk, param_pk_seed_bytes);
#endif

    // encode decode not necessary, since P1,P2 and P3 are sampled and stored in
    // bit-sliced format.
    PK_PRF((unsigned char *)bitsliced_P, param_P1_bytes + param_P2_bytes, seed_pk,
           param_pk_seed_bytes);

    uint32_t *bitsliced_P1 = bitsliced_P;
    uint32_t *bitsliced_P2 = bitsliced_P + (param_P1_bytes / 4);

    int m_legs = param_m / 32;

    // compute P1*O + P2 in position of P2
    uint32_t *bitsliced_P1O_P2 = bitsliced_P2;
    P1_times_O(p, bitsliced_P1, O, bitsliced_P1O_P2);

    // compute P3 = O^t * (P1*O + P2)
    mul_add_mat_trans_x_bitsliced_m_mat(m_legs, O, bitsliced_P1O_P2, bitsliced_P3,
                                        param_v, param_o, param_o);

    // store seed_pk in cpk
    memcpy(cpk, seed_pk, param_pk_seed_bytes);

    // compute Upper(P3) and store in cpk
    bitsliced_m_upper(
        m_legs, bitsliced_P3, bitsliced_P3_upper,
        param_o);

    memcpy(cpk + param_pk_seed_bytes, bitsliced_P3_upper, param_P3_bytes);

err:
    mayo_secure_clear(O, (N_MINUS_O_MAX)*O_MAX);
    mayo_secure_clear(bitsliced_P3, O_MAX * O_MAX * M_MAX / 2);
    return ret;
}

int mayo_expand_pk(const mayo_params_t *p, const unsigned char *cpk,
                   unsigned char *pk)
{
#ifdef MAYO_VARIANT
    (void)p;
#endif
    const int param_P1_bytes = PARAM_P1_bytes(p);
    const int param_P2_bytes = PARAM_P2_bytes(p);
    const int param_P3_bytes = PARAM_P3_bytes(p);
    const int param_pk_seed_bytes = PARAM_pk_seed_bytes(p);
    PK_PRF(pk, param_P1_bytes + param_P2_bytes, cpk, param_pk_seed_bytes);
    pk += param_P1_bytes + param_P2_bytes;
    memmove(pk, cpk + param_pk_seed_bytes, param_P3_bytes);
    return MAYO_OK;
}

int masked_mayo_expand_sk(const mayo_params_t *p, const unsigned char *csk, masked_sk_t *sk)
{

    int ret = MAYO_OK;
    // masked_S S;
    unsigned char S[PK_SEED_BYTES_MAX + O_BYTES_MAX];

    // uint32_t *bitsliced_P = sk->p;
    unsigned char O[(N_MINUS_O_MAX)*O_MAX];
    // masked_O O;

    const int param_o = PARAM_o(p);
    const int param_v = PARAM_v(p);
    const int param_O_bytes = PARAM_O_bytes(p);
    const int param_P1_bytes = PARAM_P1_bytes(p);
    const int param_P2_bytes = PARAM_P2_bytes(p);
    const int param_pk_seed_bytes = PARAM_pk_seed_bytes(p);
    const int param_sk_seed_bytes = PARAM_sk_seed_bytes(p);

#if defined(_BENCH_)
    unsigned long long t0, t1;  
#endif    

    const unsigned char *seed_sk = csk;
    unsigned char *seed_pk = S;

    shake256(S, param_pk_seed_bytes + param_O_bytes, seed_sk,
             param_sk_seed_bytes);
    decode(S + param_pk_seed_bytes, O,
           param_v * param_o); // O = S + PK_SEED_BYTES;

    unsigned char* pointO = S + param_pk_seed_bytes;

#ifdef ENABLE_CT_TESTING
    VALGRIND_MAKE_MEM_DEFINED(seed_pk, param_pk_seed_bytes);
#endif

    // #########################################################
    // for share 0 ~ *seed_pk = S.share[0].u8
    uint32_t *bitsliced_P = sk->P.share[0].u32;

    // encode decode not necessary, since P1,P2 and P3 are sampled and stored in
    // bitsliced format.
    PK_PRF((unsigned char *)bitsliced_P, param_P1_bytes + param_P2_bytes, seed_pk,
           param_pk_seed_bytes);

    uint32_t *bitsliced_P1 = bitsliced_P;
    uint32_t *bitsliced_P2 = bitsliced_P + (param_P1_bytes / 4);
    uint32_t *bitsliced_L = bitsliced_P2;

    uint32_t *bitsliced_PS = sk->P.share[1].u32;
    uint32_t *bitsliced_PS1 = bitsliced_PS;
    uint32_t *bitsliced_PS2 = bitsliced_PS + (param_P1_bytes / 4);

    memset(bitsliced_PS2, 0, param_P2_bytes);
#if defined(_BENCH_) 
    t0 = hal_get_time(); 
    randombytes((uint8_t *)bitsliced_PS, param_P1_bytes);
    for (int i = 0; i < param_P1_bytes / 4; i++)
    {
        bitsliced_P[i] = bitsliced_PS[i] ^ bitsliced_P[i];
    }

    P1P1t_times_O(p, bitsliced_P1, O, bitsliced_L);

    P1P1t_times_O(p, bitsliced_PS1, O, bitsliced_PS2);
    t1 = hal_get_time();
    printcycles("BENCH 1 :", t1-t0);          
#else
    randombytes((uint8_t *)bitsliced_PS, param_P1_bytes);
    for (int i = 0; i < param_P1_bytes / 4; i++)
    {
        bitsliced_P[i] = bitsliced_PS[i] ^ bitsliced_P[i];
    }

    P1P1t_times_O(p, bitsliced_P1, O, bitsliced_L);

    P1P1t_times_O(p, bitsliced_PS1, O, bitsliced_PS2);   
#endif
    randombytes(sk->O.share[1].u8, param_O_bytes);

    for (int i = 0; i < param_O_bytes; i++)
    {
        sk->O.share[0].u8[i] = sk->O.share[1].u8[i] ^ pointO[i];
    }

    mayo_secure_clear(S, PK_SEED_BYTES_MAX + O_BYTES_MAX);

    return ret;
}

int mayo_expand_sk(const mayo_params_t *p, const unsigned char *csk,
                   sk_t *sk)
{
    int ret = MAYO_OK;
    unsigned char S[PK_SEED_BYTES_MAX + O_BYTES_MAX];
    uint32_t *bitsliced_P = sk->p;
    unsigned char O[(N_MINUS_O_MAX)*O_MAX];

    const int param_o = PARAM_o(p);
    const int param_v = PARAM_v(p);
    const int param_O_bytes = PARAM_O_bytes(p);
    const int param_P1_bytes = PARAM_P1_bytes(p);
    const int param_P2_bytes = PARAM_P2_bytes(p);
    const int param_pk_seed_bytes = PARAM_pk_seed_bytes(p);
    const int param_sk_seed_bytes = PARAM_sk_seed_bytes(p);

#if defined(_BENCH_)
    unsigned long long t0, t1;  
#endif    


    const unsigned char *seed_sk = csk;
    unsigned char *seed_pk = S;

    shake256(S, param_pk_seed_bytes + param_O_bytes, seed_sk,
             param_sk_seed_bytes);
    decode(S + param_pk_seed_bytes, O,
           param_v * param_o); // O = S + PK_SEED_BYTES;

#ifdef ENABLE_CT_TESTING
    VALGRIND_MAKE_MEM_DEFINED(seed_pk, param_pk_seed_bytes);
#endif

    // encode decode not necessary, since P1,P2 and P3 are sampled and stored in
    // bitsliced format.
    PK_PRF((unsigned char *)bitsliced_P, param_P1_bytes + param_P2_bytes, seed_pk,
           param_pk_seed_bytes);

    uint32_t *bitsliced_P1 = bitsliced_P;
    uint32_t *bitsliced_P2 = bitsliced_P + (param_P1_bytes / 4);

#ifdef TARGET_BIG_ENDIAN
    for (int i = 0; i < (param_P1_bytes + param_P2_bytes) / 4; ++i)
    {
        bitsliced_P[i] = BSWAP32(bitsliced_P[i]);
    }
#endif

    // compute L_i = (P1 + P1^t)*O + P2
    uint32_t *bitsliced_L = bitsliced_P2;
#if defined(_BENCH_)
    t0 = hal_get_time(); 
    P1P1t_times_O(p, bitsliced_P1, O, bitsliced_L);
    t1 = hal_get_time();
    printcycles("BENCH 1 :", t1-t0);     
#else
    P1P1t_times_O(p, bitsliced_P1, O, bitsliced_L);
#endif

    // write to sk
    memcpy(sk->o, S + param_pk_seed_bytes, param_O_bytes);

#ifdef TARGET_BIG_ENDIAN
    for (int i = 0; i < (param_P1_bytes + param_P2_bytes) / 4; ++i)
    {
        bitsliced_P[i] = BSWAP32(bitsliced_P[i]);
    }
#endif

    mayo_secure_clear(S, PK_SEED_BYTES_MAX + O_BYTES_MAX);
    mayo_secure_clear(O, (N_MINUS_O_MAX)*O_MAX);
    return ret;
}

int mayo_verify(const mayo_params_t *p, const unsigned char *m,
                unsigned long long mlen, const unsigned char *sig,
                const unsigned char *cpk)
{

    unsigned char tEnc[M_BYTES_MAX];
    unsigned char t[M_MAX];
    unsigned char y[2 * M_MAX] = {0}; // extra space for reduction mod f(X)
    unsigned char s[K_MAX * N_MAX];
    alignas(64) uint32_t pk[EPK_BYTES_MAX / 4];
    unsigned char tmp[DIGEST_BYTES_MAX + SALT_BYTES_MAX];

    const int param_m = PARAM_m(p);
    const int param_n = PARAM_n(p);
    const int param_v = PARAM_v(p);
    const int param_o = PARAM_o(p);
    const int param_k = PARAM_k(p);
    const int param_m_bytes = PARAM_m_bytes(p);
    const int param_P1_bytes = PARAM_P1_bytes(p);
    const int param_P2_bytes = PARAM_P2_bytes(p);
#ifdef TARGET_BIG_ENDIAN
    const int param_P3_bytes = PARAM_P3_bytes(p);
#endif
    const int param_sig_bytes = PARAM_sig_bytes(p);
    const int param_digest_bytes = PARAM_digest_bytes(p);
    const int param_salt_bytes = PARAM_salt_bytes(p);
    const int m_legs = param_m / 32;

    int ret = mayo_expand_pk(p, cpk, (unsigned char *)pk);
    if (ret != MAYO_OK)
    {
        return MAYO_ERR;
    }

    uint32_t *bitsliced_P1 = pk;
    uint32_t *bitsliced_P2 = pk + (param_P1_bytes / 4);
    uint32_t *bitsliced_P3 = bitsliced_P2 + (param_P2_bytes / 4);

#ifdef TARGET_BIG_ENDIAN
    for (int i = 0; i < param_P1_bytes / 4; ++i)
    {
        bitsliced_P1[i] = BSWAP32(bitsliced_P1[i]);
    }
    for (int i = 0; i < param_P2_bytes / 4; ++i)
    {
        bitsliced_P2[i] = BSWAP32(bitsliced_P2[i]);
    }
    for (int i = 0; i < param_P3_bytes / 4; ++i)
    {
        bitsliced_P3[i] = BSWAP32(bitsliced_P3[i]);
    }
#endif

    // hash m
    shake256(tmp, param_digest_bytes, m, mlen);

    // compute t
    memcpy(tmp + param_digest_bytes, sig + param_sig_bytes - param_salt_bytes,
           param_salt_bytes);
    shake256(tEnc, param_m_bytes, tmp, param_digest_bytes + param_salt_bytes);
    decode(tEnc, t, param_m);

    // decode s
    decode(sig, s, param_k * param_n);

    // compute S * P * S = S* (P*S)
    alignas(32) uint32_t bitsliced_SPS[K_MAX * K_MAX * M_MAX / 8] = {0};
    bitsliced_m_calculate_PS_SPS(bitsliced_P1, bitsliced_P2, bitsliced_P3, s, param_m,
                                 param_v, param_o, param_k, bitsliced_SPS);

    // compute SPS_upper
    alignas(32) uint32_t bitsliced_SPS_upper[K_MAX * (K_MAX + 1) * M_MAX / 16];
    bitsliced_m_upper(m_legs, bitsliced_SPS, bitsliced_SPS_upper, param_k);

    int l = 0;
    for (int i = 0; i < param_k; i++)
    {
        for (int j = param_k - 1; j >= i; j--)
        {
            int pos = MAYO_POSITION_IN_UPPER_TRIAGONAL_MATRIX(i, j, param_k);
            // unbitslice SPS_upper and add to y, shifted "down" by l positions
            unsigned char temp_y[M_MAX];
            unbitslice_m_vec(m_legs, bitsliced_SPS_upper + pos * m_legs * 4, temp_y);
            for (int k = 0; k < param_m; k++)
            {
                y[l + k] ^= temp_y[k];
            }
            l++;
        }
    }

    reduce_y_mod_fX(y, param_m, param_k, PARAM_f_tail(p));

    if (memcmp(y, t, param_m) == 0)
    {
        return MAYO_OK; // good signature
    }
    return MAYO_ERR; // bad signature
}
