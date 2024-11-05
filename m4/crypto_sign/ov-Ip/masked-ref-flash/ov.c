/// @file ov.c
/// @brief The standard implementations for functions in ov.h
///
#include "params.h"

#include "ov_keypair.h"

#include "ov.h"

#include "blas.h"

#include "ov_blas.h"
#include "masked.h"

#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <assert.h>

#include "utils_prng.h"
#include "utils_hash.h"
#include "utils_malloc.h"

#define _BACK_SUBSTITUTION_


#define MAX_ATTEMPT_VINEGAR  256

// #define _BLINDMAT_
// #define _MODIFIY_V_AFTER_USAGE_
// #define _BENCH_PRFS_

#if defined(_BENCH_PRFS_)
    #include "aes_ctr.h"
    // #include <stdio.h>
    #include "hal.h"
    #include "sendfn.h"
    #define printcycles(S, U) send_unsignedll((S), (U))
    #define PK_PRF AES_128_CTR
#endif

// #define _BENCH_
#if defined(_BENCH_)
    #include "hal.h"
    #include "sendfn.h"
    #define printcycles(S, U) send_unsignedll((S), (U))
#endif

#if defined(_VALGRIND_)
#include "valgrind/memcheck.h"
#endif

int ov_sign( uint8_t * signature , const sk_t * sk , const uint8_t * message , unsigned mlen )
{
    // allocate temporary storage.
    uint8_t mat_l1[_O*_O_BYTE];
    // uint8_t mat_l1_cop1[_O*_O_BYTE];
    // uint8_t mat_l1_cop2[_O*_O_BYTE];
    uint8_t salt[_SALT_BYTE];
    randombytes( salt , _SALT_BYTE );
    #if defined(_VALGRIND_)
    VALGRIND_MAKE_MEM_UNDEFINED(salt, _SALT_BYTE );  // mark secret data as undefined data
    VALGRIND_MAKE_MEM_UNDEFINED(sk, OV_SECRETKEYBYTES );  // mark secret data as undefined data
    #endif
    uint8_t vinegar[_V_BYTE];
    uint8_t r_l1_F1[_O_BYTE] = {0};
    (void ) r_l1_F1;
    uint8_t y[_PUB_N_BYTE];
    uint8_t x_o1[_O_BYTE];

#if defined(_BLINDMAT_) 
    uint8_t blindmat[_PK_P2_BYTE];
    unsigned long int j;    
#endif

#if defined(_BENCH_)
    unsigned long long t0, t1;  
#endif

    // uint8_t rblind[_O_BYTE];

    uint8_t rhs_cmp2[_O_BYTE] = {0};                            // 44
    uint8_t rhs_cmp3[_O_BYTE] = {0};                            // 44
    // what about hash(message) ???
    // needs improvement!!!
    uint8_t mbuf[(59+_SALT_BYTE+LEN_SKSEED+1)*MASKING_N] = {0}; // (mlen+16+32+1)*2
    masked_vinegar mvinegar = {0};                              // 68 * 2
    masked_buffer masked_buf = {0};                             // 131648
    // masked computation on each share
    uint8_t mat_l1_tmp[_O*_O_BYTE] = {0};                       // 1936
    
    // generate shares ##################################
    // masked_sk_seed sk_seed;

    // ########## seed ##########
    // generate share seed0
    randombytes(masked_buf.share.u8, LEN_SKSEED);
    unsigned long int i;

    // #################################################


#if defined(_MUL_WITH_MULTAB_)
    uint8_t multabs[(_V)*32] __attribute__((aligned(32)));
#endif

#if defined(_LDU_DECOMPOSE_)&& (!defined(_BACK_SUBSTITUTION_))
    uint8_t submat_A[(_O/2)*(_O_BYTE/2)];
    uint8_t submat_B[(_O/2)*(_O_BYTE/2)];
    uint8_t submat_C[(_O/2)*(_O_BYTE/2)];
    uint8_t submat_D[(_O/2)*(_O_BYTE/2)];
#endif

    hash_ctx h_m_salt_secret;
    hash_ctx h_vinegar_copy;
    // The computation:  H(M||salt)  -->   y  --C-map-->   x   --T-->   w
    hash_init(&h_m_salt_secret);
    hash_update(&h_m_salt_secret, message, mlen);
    hash_update(&h_m_salt_secret, salt, _SALT_BYTE);
    hash_ctx_copy(&h_vinegar_copy, &h_m_salt_secret);
    hash_final_digest( y , _PUB_M_BYTE , &h_m_salt_secret);  // H(M||salt)

    memcpy(mbuf, message, mlen); // M
    memcpy(mbuf + mlen, salt, _SALT_BYTE); // M||salt
    memcpy(mbuf + mlen + _SALT_BYTE + LEN_SKSEED + 1, mbuf, mlen + _SALT_BYTE); // // M||salt ... M||salt
    memcpy(mbuf + mlen + _SALT_BYTE , masked_buf.share.u8, LEN_SKSEED); // // M||salt||seed_1 ... M||salt

    // compute share seed1 = seed + seed0
    for(i = 0; i < LEN_SKSEED; i++) {
        masked_buf.share.u8[i] = masked_buf.share.u8[i] ^ sk->sk_seed[i];
    }    

    memcpy(mbuf + mlen + _SALT_BYTE + LEN_SKSEED + 1  + mlen + _SALT_BYTE, masked_buf.share.u8, LEN_SKSEED); // // M||salt||seed_1 ... M||salt||seed_2

    // hash_update(&h_vinegar_copy, sk->sk_seed, LEN_SKSEED );   // H(M||salt||sk_seed ...

    uint8_t ctr = 0;  // counter for generating vinegar
    unsigned n_attempt = 0;
    // unsigned l1_succ = 0;
    unsigned l2_succ = 0;
    unsigned l3_succ = 0;
    while( MAX_ATTEMPT_VINEGAR > n_attempt++  ) {
        // hash_ctx h_vinegar;
        // hash_ctx_copy(&h_vinegar, &h_vinegar_copy);
        // hash_update(&h_vinegar, &ctr, 1 );                  // H(M||salt||sk_seed||ctr ...

        memcpy(mbuf + mlen + _SALT_BYTE + LEN_SKSEED, &ctr, 1);

        memcpy(mbuf + (mlen + _SALT_BYTE + LEN_SKSEED)*2 + 1, &ctr, 1);

#if defined(_BENCH_)      
        t0 = hal_get_time();
        masked_hash_g_len(&mvinegar, _V_BYTE, (const uint8_t *) mbuf, mlen+_SALT_BYTE+LEN_SKSEED+1);
        t1 = hal_get_time();
        printcycles("BENCH 1 :", t1-t0); 
#else
        masked_hash_g_len(&mvinegar, _V_BYTE, (const uint8_t *) mbuf, mlen+_SALT_BYTE+LEN_SKSEED+1);
#endif

        ctr++;
        #if defined(_VALGRIND_)
        VALGRIND_MAKE_MEM_UNDEFINED(vinegar, _V_BYTE );  // mark secret data as undefined data
        #endif

#if defined(_BACK_SUBSTITUTION_)

// linear system:
#if defined(_MUL_WITH_MULTAB_)
        gfv_generate_multabs( multabs , vinegar , _V );
// matrix
        gfmat_prod_multab( mat_l1 , sk->L , _O*_O_BYTE , _V , multabs );
// constant
    // Given vinegars, evaluate P1 with the vinegars
        batch_quad_trimat_eval_multab( r_l1_F1, sk->P1, multabs, _V, _O_BYTE );
#else
// matrix

        // v = v0 + v1
        for(i = 0; i < _V_BYTE; i++) {
            vinegar[i] = mvinegar.share[0].u8[i] ^ mvinegar.share[1].u8[i];
        }

#if defined(_BENCH_) 
        t0 = hal_get_time();
#if defined(_BLINDMAT_) 
        // ########################## exclude 0 from possible values because it has no inverse ######################################
        // randombytes(masked_buf.share.u8, _O);
        randombytes_no_zero(masked_buf.share.u8, _O);
        // multiply to matrix entries (consider ordering of P1)
        for(j = 0; j < _O; j++) {
            for(i = 0; i < _O_BYTE * _V; i++) {
                blindmat[j+i*_O] = gf256_mul(sk->L[j+i*_O],masked_buf.share.u8[j]);
            }
        }
        gfmat_prod(mat_l1 , blindmat , _O*_O_BYTE , _V , mvinegar.share[0].u8 );

        gfmat_prod(mat_l1_tmp , blindmat , _O*_O_BYTE , _V , mvinegar.share[1].u8 );

        for(i = 0; i < _O_BYTE*_O; i++) {
            mat_l1[i] = mat_l1[i] ^ mat_l1_tmp[i];
        }
        // remove blinding from result
        for(j = 0; j < _O; j++) {
            for(i = 0; i < _O_BYTE; i++) {
                mat_l1[j+i*_O]= gf256_mul(mat_l1[j+i*_O], gf256_inv(masked_buf.share.u8[j]));                
            }
        }

#else

#if defined(_BENCH_PRFS_)
        unsigned long long t0, t1;
        uint8_t seed[4];
        
        t0 = hal_get_time();
        randombytes(masked_buf.share.u8, _PK_P2_BYTE);
        t1 = hal_get_time();
        printcycles("randombytes(_PK_P2_BYTE) :", t1-t0);        

        randombytes(seed, 4);

        t0 = hal_get_time();
        PK_PRF(masked_buf.share.u8, _PK_P2_BYTE, seed, 4);
        t1 = hal_get_time();
        printcycles("PK_PRF(_PK_P2_BYTE) :", t1-t0);   

        t0 = hal_get_time();
        shake256(masked_buf.share.u8, _PK_P2_BYTE, seed, 4);
        t1 = hal_get_time();
        printcycles("shake256(_PK_P2_BYTE) :", t1-t0);       
#else   
        // generate share L0
        randombytes(masked_buf.share.u8, _PK_P2_BYTE);
#endif

        // v0*L0
        gfmat_prod(mat_l1, masked_buf.share.u8, _O*_O_BYTE, _V, mvinegar.share[0].u8);
        // v1*L0
        gfmat_prod(mat_l1_tmp, masked_buf.share.u8, _O*_O_BYTE, _V, mvinegar.share[1].u8);
        // v0*L0 + v1*L0
        for(i = 0; i < _O_BYTE*_O; i++) {
            mat_l1[i] = mat_l1[i] ^ mat_l1_tmp[i];
        }
        // compute share L1
        for(i = 0; i < _PK_P2_BYTE; i++) {
                masked_buf.share.u8[i] = masked_buf.share.u8[i] ^ sk->L[i];
        }
        // v0*L1
        gfmat_prod(mat_l1_tmp, masked_buf.share.u8, _O*_O_BYTE, _V, mvinegar.share[0].u8);
        // v0*L0 + v1*L0 + v0*L1
        for(i = 0; i < _O_BYTE*_O; i++) {
            mat_l1[i] = mat_l1[i] ^ mat_l1_tmp[i];
        }
        // v1*L1
        gfmat_prod(mat_l1_tmp, masked_buf.share.u8, _O*_O_BYTE, _V, mvinegar.share[1].u8);
        // v0*L0 + v1*L0 + v0*L0 + v1*L0 (should be equal to old v*L computation)
        for(i = 0; i < _O_BYTE*_O; i++) {
            mat_l1[i] = mat_l1[i] ^ mat_l1_tmp[i];
        }

        // end unmasked and masked v*L computation ###########
#endif
        t1 = hal_get_time();
        printcycles("BENCH 2 :", t1-t0);
#else

#if defined(_BLINDMAT_) 
        // ########################## exclude 0 from possible values because it has no inverse ######################################
        // randombytes(masked_buf.share.u8, _O);
        randombytes_no_zero(masked_buf.share.u8, _O);
        // multiply to matrix entries (consider ordering of P1)
        for(j = 0; j < _O; j++) {
            for(i = 0; i < _O_BYTE * _V; i++) {
                blindmat[j+i*_O] = gf256_mul(sk->L[j+i*_O],masked_buf.share.u8[j]);
            }
        }
        gfmat_prod(mat_l1 , blindmat , _O*_O_BYTE , _V , mvinegar.share[0].u8 );

        gfmat_prod(mat_l1_tmp , blindmat , _O*_O_BYTE , _V , mvinegar.share[1].u8 );

        for(i = 0; i < _O_BYTE*_O; i++) {
            mat_l1[i] = mat_l1[i] ^ mat_l1_tmp[i];
        }
        // remove blinding from result
        for(j = 0; j < _O; j++) {
            for(i = 0; i < _O_BYTE; i++) {
                mat_l1[j+i*_O]= gf256_mul(mat_l1[j+i*_O], gf256_inv(masked_buf.share.u8[j]));
            }
        }
#else

#if defined(_BENCH_PRFS_)
        unsigned long long t0, t1;
        uint8_t seed[4];
        
        t0 = hal_get_time();
        randombytes(masked_buf.share.u8, _PK_P2_BYTE);
        t1 = hal_get_time();
        printcycles("randombytes(_PK_P2_BYTE) :", t1-t0);        

        randombytes(seed, 4);

        t0 = hal_get_time();
        PK_PRF(masked_buf.share.u8, _PK_P2_BYTE, seed, 4);
        t1 = hal_get_time();
        printcycles("PK_PRF(_PK_P2_BYTE) :", t1-t0);   

        t0 = hal_get_time();
        shake256(masked_buf.share.u8, _PK_P2_BYTE, seed, 4);
        t1 = hal_get_time();
        printcycles("shake256(_PK_P2_BYTE) :", t1-t0);       
#else   
        // generate share L0
        randombytes(masked_buf.share.u8, _PK_P2_BYTE);
#endif

        // v0*L0
        gfmat_prod(mat_l1, masked_buf.share.u8, _O*_O_BYTE, _V, mvinegar.share[0].u8);
        // v1*L0
        gfmat_prod(mat_l1_tmp, masked_buf.share.u8, _O*_O_BYTE, _V, mvinegar.share[1].u8);
        // v0*L0 + v1*L0
        for(i = 0; i < _O_BYTE*_O; i++) {
            mat_l1[i] = mat_l1[i] ^ mat_l1_tmp[i];
        }
        // compute share L1
        for(i = 0; i < _PK_P2_BYTE; i++) {
                masked_buf.share.u8[i] = masked_buf.share.u8[i] ^ sk->L[i];
        }
        // v0*L1
        gfmat_prod(mat_l1_tmp, masked_buf.share.u8, _O*_O_BYTE, _V, mvinegar.share[0].u8);
        // v0*L0 + v1*L0 + v0*L1
        for(i = 0; i < _O_BYTE*_O; i++) {
            mat_l1[i] = mat_l1[i] ^ mat_l1_tmp[i];
        }
        // v1*L1
        gfmat_prod(mat_l1_tmp, masked_buf.share.u8, _O*_O_BYTE, _V, mvinegar.share[1].u8);
        // v0*L0 + v1*L0 + v0*L0 + v1*L0 (should be equal to old v*L computation)
        for(i = 0; i < _O_BYTE*_O; i++) {
            mat_l1[i] = mat_l1[i] ^ mat_l1_tmp[i];
        }
        // end unmasked and masked v*L computation ###########
#endif

#endif




// constant
        // Given vinegars, evaluate P1 with the vinegars (unmasked)


#if defined(_BENCH_) 
        t0 = hal_get_time();
#if defined(_BLINDMAT_) 
        // ########################## exclude 0 from possible values because it has no inverse ######################################
        // randombytes(masked_buf.share.u8, _O);
        randombytes_no_zero(masked_buf.share.u8, _O);
        // multiply to matrix entries (consider ordering of P1)
        for(j = 0; j < _O; j++) {
            for(i = 0; i < N_TRIANGLE_TERMS(_V); i++) {
                blindmat[j+i*_O] = gf256_mul(sk->P1[j+i*_O],masked_buf.share.u8[j]);
            }
        }
        batch_quad_trimat_eval( r_l1_F1, blindmat, vinegar, _V, _O_BYTE );
        // remove blinding from result
        for(j = 0; j < _O; j++) {
            r_l1_F1[j]= gf256_mul(r_l1_F1[j], gf256_inv(masked_buf.share.u8[j]));
            // r_l1_F1[j]= gf256_mul(r_l1_F1[j], masked_buf.share.u8[j]);
        }
        // split in 2 shares for next step
        randombytes(rhs_cmp2, _O_BYTE);
        for(i = 0; i < _O; i++) {
            rhs_cmp3[i] = rhs_cmp2[i] ^ r_l1_F1[i];
        }

#else 

        ////// masked v*P*v computation, where P is masked (Option 2)
        //batch_quad_trimat_eval(r_l1_F1, sk->P1, vinegar, _V, _O_BYTE );
        ////// Instead we mask the Public Matrices, so that they not known to the attack anymore, preventing our profiling attack
        // generate share P1.0
        //memset(masked_buf.share.u8, 0, _PK_P1_BYTE);
        randombytes(masked_buf.share.u8, _PK_P1_BYTE);        
        
        batch_quad_trimat_eval(rhs_cmp2, masked_buf.share.u8, vinegar, _V, _O_BYTE );

        // compute share 1 = P1 + share 0
        for(i = 0; i < _PK_P1_BYTE; i++) {
               masked_buf.share.u8[i] = masked_buf.share.u8[i] ^ sk->P1[i];
        }  

        batch_quad_trimat_eval(rhs_cmp3, masked_buf.share.u8, vinegar, _V, _O_BYTE );
        // add together to double check for debugging, but continue with shares
        for(i = 0; i < _O; i++) {
           r_l1_F1[i] = rhs_cmp2[i] ^ rhs_cmp3[i];
        }

#endif
        t1 = hal_get_time();
        printcycles("BENCH 3 :", t1-t0); 

#else
#if defined(_BLINDMAT_) 
        // ########################## exclude 0 from possible values because it has no inverse ######################################
        // randombytes(masked_buf.share.u8, _O);
        randombytes_no_zero(masked_buf.share.u8, _O);
        // multiply to matrix entries (consider ordering of P1)
        for(j = 0; j < _O; j++) {
            for(i = 0; i < N_TRIANGLE_TERMS(_V); i++) {
                blindmat[j+i*_O] = gf256_mul(sk->P1[j+i*_O],masked_buf.share.u8[j]);
            }
        }
        batch_quad_trimat_eval( r_l1_F1, blindmat, vinegar, _V, _O_BYTE );
        // remove blinding from result
        for(j = 0; j < _O; j++) {
            r_l1_F1[j]= gf256_mul(r_l1_F1[j], gf256_inv(masked_buf.share.u8[j]));
        }
        // split in 2 shares for next step
        randombytes(rhs_cmp2, _O_BYTE);
        for(i = 0; i < _O; i++) {
            rhs_cmp3[i] = rhs_cmp2[i] ^ r_l1_F1[i];
        }

#else 

        ////// masked v*P*v computation, where P is masked (Option 2)
        //batch_quad_trimat_eval(r_l1_F1, sk->P1, vinegar, _V, _O_BYTE );
        ////// Instead we mask the Public Matrices, so that they not known to the attack anymore, preventing our profiling attack
        // generate share P1.0
        //memset(masked_buf.share.u8, 0, _PK_P1_BYTE);
        randombytes(masked_buf.share.u8, _PK_P1_BYTE);        
        
        batch_quad_trimat_eval(rhs_cmp2, masked_buf.share.u8, vinegar, _V, _O_BYTE );

        // compute share 1 = P1 + share 0
        for(i = 0; i < _PK_P1_BYTE; i++) {
               masked_buf.share.u8[i] = masked_buf.share.u8[i] ^ sk->P1[i];
        }  

        batch_quad_trimat_eval(rhs_cmp3, masked_buf.share.u8, vinegar, _V, _O_BYTE );
        // add together to double check for debugging, but continue with shares
        for(i = 0; i < _O; i++) {
           r_l1_F1[i] = rhs_cmp2[i] ^ rhs_cmp3[i];
        }

#endif

#endif

#endif

#if defined(_BENCH_) 
        t0 = hal_get_time();
        //gf256v_add( r_l1_F1 , y , _O_BYTE );    // substract the contribution from vinegar variables
        //memcpy(rhs_cmp2, r_l1_F1, _O_BYTE);
        //memcpy(rhs_cmp3, r_l1_F1, _O_BYTE);
        gf256v_add( rhs_cmp2 , y , _O_BYTE );    // substract the contribution from vinegar variables (one share), leave the other share solo and compute solution for both
        // gf256mat_gaussian_elim alters the matrix, so we need to make copies for the shares (for now)
        memcpy( masked_buf.share.u8 , mat_l1 , _O*_O_BYTE );
        memcpy( masked_buf.share.u8 + _O*_O_BYTE, mat_l1 , _O*_O_BYTE );
        // in masked version compute solution in two shares
        // first Lx0 = y0 + t
        // second Lx1 = y1
        // Then L(x0+x1)=y0+y1+t = y+t as supposed to be
#if _GFSIZE == 256
        //l1_succ = gf256mat_gaussian_elim(mat_l1 , r_l1_F1, _O);
        l2_succ = gf256mat_gaussian_elim(masked_buf.share.u8, rhs_cmp2, _O);
        l3_succ = gf256mat_gaussian_elim(masked_buf.share.u8 + _O*_O_BYTE, rhs_cmp3, _O);
#if defined(_VALGRIND_)
        VALGRIND_MAKE_MEM_DEFINED(&l1_succ, sizeof(unsigned) );  // this is ok cause it's reject sampling
#endif
        //if( !l1_succ) continue;
        if( !l2_succ || !l3_succ) continue;
        //gf256mat_back_substitute(r_l1_F1, mat_l1, _O);
        gf256mat_back_substitute(rhs_cmp2, masked_buf.share.u8, _O);
        gf256mat_back_substitute(rhs_cmp3, masked_buf.share.u8 + _O*_O_BYTE, _O);
        //memcpy( x_o1 , r_l1_F1 , _O_BYTE );
        memcpy( masked_buf.share.u8 , rhs_cmp2 , _O_BYTE );
        memcpy( masked_buf.share.u8 + _O_BYTE, rhs_cmp3 , _O_BYTE );

        for(i = 0; i < _O_BYTE; i++) {
            x_o1[i] =masked_buf.share.u8[i] ^ masked_buf.share.u8[i+_O_BYTE];
        }


#elif _GFSIZE == 16
        l1_succ = gf16mat_gaussian_elim(mat_l1 , r_l1_F1, _O);
        #if defined(_VALGRIND_)
        VALGRIND_MAKE_MEM_DEFINED(&l1_succ, sizeof(unsigned) );  // this is ok cause it's reject sampling
        #endif
        if( !l1_succ ) continue;
        gf16mat_back_substitute(r_l1_F1, mat_l1, _O);
        memcpy( x_o1 , r_l1_F1 , _O_BYTE );
#else
error -- _GFSIZE
#endif
        t1 = hal_get_time();
        printcycles("BENCH 4 :", t1-t0); 

#else
        //gf256v_add( r_l1_F1 , y , _O_BYTE );    // substract the contribution from vinegar variables
        //memcpy(rhs_cmp2, r_l1_F1, _O_BYTE);
        //memcpy(rhs_cmp3, r_l1_F1, _O_BYTE);
        gf256v_add( rhs_cmp2 , y , _O_BYTE );    // substract the contribution from vinegar variables (one share), leave the other share solo and compute solution for both
        // gf256mat_gaussian_elim alters the matrix, so we need to make copies for the shares (for now)
        memcpy( masked_buf.share.u8 , mat_l1 , _O*_O_BYTE );
        memcpy( masked_buf.share.u8 + _O*_O_BYTE, mat_l1 , _O*_O_BYTE );
        // in masked version compute solution in two shares
        // first Lx0 = y0 + t
        // second Lx1 = y1
        // Then L(x0+x1)=y0+y1+t = y+t as supposed to be
#if _GFSIZE == 256
        //l1_succ = gf256mat_gaussian_elim(mat_l1 , r_l1_F1, _O);
        l2_succ = gf256mat_gaussian_elim(masked_buf.share.u8, rhs_cmp2, _O);
        l3_succ = gf256mat_gaussian_elim(masked_buf.share.u8 + _O*_O_BYTE, rhs_cmp3, _O);
#if defined(_VALGRIND_)
        VALGRIND_MAKE_MEM_DEFINED(&l1_succ, sizeof(unsigned) );  // this is ok cause it's reject sampling
#endif
        //if( !l1_succ) continue;
        if( !l2_succ || !l3_succ) continue;
        //gf256mat_back_substitute(r_l1_F1, mat_l1, _O);
        gf256mat_back_substitute(rhs_cmp2, masked_buf.share.u8, _O);
        gf256mat_back_substitute(rhs_cmp3, masked_buf.share.u8 + _O*_O_BYTE, _O);
        //memcpy( x_o1 , r_l1_F1 , _O_BYTE );
        memcpy( masked_buf.share.u8 , rhs_cmp2 , _O_BYTE );
        memcpy( masked_buf.share.u8 + _O_BYTE, rhs_cmp3 , _O_BYTE );

        for(i = 0; i < _O_BYTE; i++) {
            x_o1[i] =masked_buf.share.u8[i] ^ masked_buf.share.u8[i+_O_BYTE];
        }


#elif _GFSIZE == 16
        l1_succ = gf16mat_gaussian_elim(mat_l1 , r_l1_F1, _O);
        #if defined(_VALGRIND_)
        VALGRIND_MAKE_MEM_DEFINED(&l1_succ, sizeof(unsigned) );  // this is ok cause it's reject sampling
        #endif
        if( !l1_succ ) continue;
        gf16mat_back_substitute(r_l1_F1, mat_l1, _O);
        memcpy( x_o1 , r_l1_F1 , _O_BYTE );
#else
error -- _GFSIZE
#endif

#endif
        break;
    }
    hash_final_digest( NULL , 0 , &h_vinegar_copy); // free
    if( MAX_ATTEMPT_VINEGAR <= n_attempt ) return -1;

#else // defined(_BACK_SUBSTITUTION_)

#if defined(_MUL_WITH_MULTAB_)
        gfv_generate_multabs( multabs , vinegar , _V );
        gfmat_prod_multab( mat_l1 , sk->L , _O*_O_BYTE , _V , multabs );
#else
        gfmat_prod( mat_l1 , sk->L , _O*_O_BYTE , _V , vinegar );
#endif

#if defined(_LDU_DECOMPOSE_)
#if _GFSIZE == 256
        l1_succ = gf256mat_LDUinv( submat_B , submat_A , submat_D , submat_C , mat_l1 , _O );  // check if the linear equation solvable
#elif _GFSIZE == 16
        l1_succ = gf16mat_LDUinv( submat_B , submat_A , submat_D , submat_C , mat_l1 , _O );  // check if the linear equation solvable
#else
error -- _GFSIZE
#endif
#else
        l1_succ = gfmat_inv( mat_l1 , mat_l1 , _O );         // check if the linear equation solvable
#endif
        #if defined(_VALGRIND_)
        VALGRIND_MAKE_MEM_DEFINED(&l1_succ, sizeof(unsigned) );  // this is of cause it's reject sampling
        #endif
	if( l1_succ ) break;
    }
    hash_final_digest( NULL , 0 , &h_vinegar_copy); // free
    if( MAX_ATTEMPT_VINEGAR <= n_attempt ) return -1;

    // Given vinegars, evaluate P1 with the (secret?) vinegars
#if defined(_MUL_WITH_MULTAB_)
    batch_quad_trimat_eval_multab( r_l1_F1, sk->P1, multabs, _V, _O_BYTE );
#else
    batch_quad_trimat_eval( r_l1_F1, sk->P1, vinegar, _V, _O_BYTE );
#endif
    do {
        // The computation:  H(M||salt)  -->   y  --C-map-->   x   --T-->   w
        // Central Map:
        // calculate x_o1
        gf256v_add( y , r_l1_F1 , _O_BYTE );    // substract the contribution from vinegar variables
#if defined(_LDU_DECOMPOSE_)
#if _GFSIZE == 256
        gf256mat_LDUinv_prod( x_o1 , submat_B , submat_A , submat_D , submat_C , y , _O_BYTE );
#elif _GFSIZE == 16
        gf16mat_LDUinv_prod( x_o1 , submat_B , submat_A , submat_D , submat_C , y , _O_BYTE );
#else
error -- _GFSIZE
#endif
#else
        gfmat_prod( x_o1 , mat_l1, _O_BYTE , _O , y );
#endif
    } while(0);

#endif // defined(_BACK_SUBSTITUTION_)

#if defined(_BENCH_) 
    t0 = hal_get_time();
    //  w = T^-1 * x
    uint8_t * w = signature;   // [_PUB_N_BYTE];

    // masked vinegar
    memcpy( w , mvinegar.share[0].u8 , _V_BYTE );
    gf256v_add(w, mvinegar.share[1].u8, _V_BYTE );

#if defined(_MODIFIY_V_AFTER_USAGE_)    
    gf256v_add(w, mat_l1_tmp, _V_BYTE);    
#endif

    memcpy( w + _V_BYTE , x_o1 , _O_BYTE );

    // masked oil space
    // generate share t1.0
    randombytes(masked_buf.share.u8, _V_BYTE*_O);
    gfmat_prod(y, masked_buf.share.u8, _V_BYTE , _O , x_o1 );

    gf256v_add(w, y, _V_BYTE );

    // compute share t1.1
    for(i = 0; i < (_V_BYTE*_O); i++) {
            masked_buf.share.u8[i] = masked_buf.share.u8[i] ^ sk->t1[i];
    }   
    gfmat_prod(y, masked_buf.share.u8, _V_BYTE , _O , x_o1 );

    gf256v_add(w, y, _V_BYTE );

#if defined(_MODIFIY_V_AFTER_USAGE_)     
    gf256v_add(w, mat_l1_tmp, _V_BYTE);    
#endif        

    t1 = hal_get_time();
    printcycles("BENCH 5 :", t1-t0);

#else
    //  w = T^-1 * x
    uint8_t * w = signature;   // [_PUB_N_BYTE];

    // masked vinegar
    memcpy( w , mvinegar.share[0].u8 , _V_BYTE );
    gf256v_add(w, mvinegar.share[1].u8, _V_BYTE );

#if defined(_MODIFIY_V_AFTER_USAGE_)    
    gf256v_add(w, mat_l1_tmp, _V_BYTE);    
#endif

    memcpy( w + _V_BYTE , x_o1 , _O_BYTE );

    // masked oil space
    // generate share t1.0
    randombytes(masked_buf.share.u8, _V_BYTE*_O);
    gfmat_prod(y, masked_buf.share.u8, _V_BYTE , _O , x_o1 );

    gf256v_add(w, y, _V_BYTE );

    // compute share t1.1
    for(i = 0; i < (_V_BYTE*_O); i++) {
            masked_buf.share.u8[i] = masked_buf.share.u8[i] ^ sk->t1[i];
    }   
    gfmat_prod(y, masked_buf.share.u8, _V_BYTE , _O , x_o1 );

    gf256v_add(w, y, _V_BYTE );

#if defined(_MODIFIY_V_AFTER_USAGE_)     
    gf256v_add(w, mat_l1_tmp, _V_BYTE);    
#endif    

#endif



    // return: signature <- w || salt.
    memcpy( signature + _PUB_N_BYTE , salt , _SALT_BYTE );

    return 0;
}


static
int _ov_verify( const uint8_t * message , unsigned mlen , const uint8_t * salt , const unsigned char * digest_ck )
{
    unsigned char correct[_PUB_M_BYTE];
    hash_ctx hctx;
    hash_init(&hctx);
    hash_update(&hctx, message, mlen);
    hash_update(&hctx, salt, _SALT_BYTE);
    hash_final_digest(correct, _PUB_M_BYTE, &hctx);  // H( message || salt )

    // check consistency.
    unsigned char cc = 0;
    for(unsigned i=0;i<_PUB_M_BYTE;i++) {
        cc |= (digest_ck[i]^correct[i]);
    }
    return (0==cc)? 0: -1;
}


#if !(defined(_OV_PKC) || defined(_OV_PKC_SKC)) || !defined(_SAVE_MEMORY_)
int ov_verify( const uint8_t * message , unsigned mlen , const uint8_t * signature , const pk_t * pk )
{
    #if defined(_VALGRIND_)
    VALGRIND_MAKE_MEM_DEFINED(signature, OV_SIGNATUREBYTES );  // mark signature as public data
    #endif
    unsigned char digest_ck[_PUB_M_BYTE];
    ov_publicmap( digest_ck , pk->pk , signature );

    return _ov_verify( message , mlen , signature+_PUB_N_BYTE , digest_ck );
}
#endif

#if defined(_OV_PKC_SKC)
int ov_expand_and_sign( uint8_t * signature , const csk_t * csk , const uint8_t * message , unsigned mlen )
{
    sk_t _sk;
    sk_t * sk = &_sk;
    expand_sk( sk, csk->pk_seed , csk->sk_seed );   // generating classic secret key.

    int r = ov_sign( signature , sk , message , mlen );
    return r;
}
#endif

#if defined(_OV_PKC) || defined(_OV_PKC_SKC)
int ov_expand_and_verify( const uint8_t * message , unsigned mlen , const uint8_t * signature , const cpk_t * cpk )
{

#ifdef _SAVE_MEMORY_
    unsigned char digest_ck[_PUB_M_BYTE];
    ov_publicmap_pkc( digest_ck , cpk , signature );
    return _ov_verify( message , mlen , signature+_PUB_N_BYTE , digest_ck );
#else
    pk_t _pk;
    pk_t * pk = &_pk;
    #if _GFSIZE == 16  && (defined(_BLAS_NEON_) || defined(_BLAS_M4F_))
        uint8_t xi[_PUB_N];
        for(int i=0;i<_PUB_N;i++) xi[i] = gfv_get_ele( signature , i );
        expand_pk_predicate( pk , cpk , xi );
    #else
        expand_pk( pk , cpk );
    #endif
    return ov_verify( message , mlen , signature , pk );
#endif
}
#endif


