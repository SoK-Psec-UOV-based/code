/// @file ov.c
/// @brief The standard implementations for functions in ov.h
///
#include "params.h"

#include "ov_keypair.h"

#include "ov.h"

#include "blas.h"

#include "ov_blas.h"

#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "utils_prng.h"
#include "utils_hash.h"
#include "utils_malloc.h"

#define _BACK_SUBSTITUTION_

#define MAX_ATTEMPT_VINEGAR  256

// #define _BENCH_
#if defined(_BENCH_)
    #include "hal.h"
    #include "sendfn.h"
    #define printcycles(S, U) send_unsignedll((S), (U))
#endif
/////////////////////////////

#if defined(_VALGRIND_)
#include "valgrind/memcheck.h"
#endif

int ov_sign( uint8_t * signature , const sk_t * sk , const uint8_t * message , unsigned mlen )
// int ov_sign( uint8_t * signature ,  sk_t * sk , const uint8_t * message , unsigned mlen )
{
    // allocate temporary storage.
    uint8_t mat_l1[_O*_O_BYTE];
    uint8_t salt[_SALT_BYTE];
    randombytes( salt , _SALT_BYTE );
    #if defined(_VALGRIND_)
    VALGRIND_MAKE_MEM_UNDEFINED(salt, _SALT_BYTE );  // mark secret data as undefined data
    VALGRIND_MAKE_MEM_UNDEFINED(sk, OV_SECRETKEYBYTES );  // mark secret data as undefined data
    #endif
    uint8_t vinegar[_V_BYTE];
    uint8_t r_l1_F1[_O_BYTE] = {0};
    uint8_t y[_PUB_N_BYTE];
    uint8_t x_o1[_O_BYTE];

#if defined(_MUL_WITH_MULTAB_)
    uint8_t multabs[(_V)*32] __attribute__((aligned(32)));
#endif

#if defined(_BENCH_)
    unsigned long long t0, t1;  
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
    hash_init  (&h_m_salt_secret);
    hash_update(&h_m_salt_secret, message, mlen);
    hash_update(&h_m_salt_secret, salt, _SALT_BYTE);
    hash_ctx_copy(&h_vinegar_copy, &h_m_salt_secret);
    hash_final_digest( y , _PUB_M_BYTE , &h_m_salt_secret);  // H(M||salt)

    hash_update(&h_vinegar_copy, sk->sk_seed, LEN_SKSEED );   // H(M||salt||sk_seed ...

    uint8_t ctr = 0;  // counter for generating vinegar
    unsigned n_attempt = 0;
    unsigned l1_succ = 0;
    while( MAX_ATTEMPT_VINEGAR > n_attempt++  ) {
        hash_ctx h_vinegar;
        hash_ctx_copy(&h_vinegar, &h_vinegar_copy);
        hash_update(&h_vinegar, &ctr, 1 );                  // H(M||salt||sk_seed||ctr ...
#if defined(_BENCH_)      
        t0 = hal_get_time();
        hash_final_digest( vinegar, _V_BYTE , &h_vinegar);  // H(M||salt||sk_seed||ctr)
        t1 = hal_get_time();
        printcycles("BENCH 1 :", t1-t0); 
#else
        hash_final_digest( vinegar, _V_BYTE , &h_vinegar);  // H(M||salt||sk_seed||ctr)    
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
#if defined(_BENCH_) 
        t0 = hal_get_time();
        gfmat_prod( mat_l1 , sk->L , _O*_O_BYTE , _V , vinegar );
        t1 = hal_get_time();
        printcycles("BENCH 2 :", t1-t0); 
#else
        gfmat_prod( mat_l1 , sk->L , _O*_O_BYTE , _V , vinegar );
#endif


// constant
    // Given vinegars, evaluate P1 with the vinegars
#if defined(_BENCH_) 
        t0 = hal_get_time();
        batch_quad_trimat_eval( r_l1_F1, sk->P1, vinegar, _V, _O_BYTE );
        t1 = hal_get_time();
        printcycles("BENCH 3 :", t1-t0); 
#else
        batch_quad_trimat_eval( r_l1_F1, sk->P1, vinegar, _V, _O_BYTE );
#endif



#endif
#if defined(_BENCH_) 
        t0 = hal_get_time();
        gf256v_add( r_l1_F1 , y , _O_BYTE );    // substract the contribution from vinegar variables

#if _GFSIZE == 256
        l1_succ = gf256mat_gaussian_elim(mat_l1 , r_l1_F1, _O);
        #if defined(_VALGRIND_)
        VALGRIND_MAKE_MEM_DEFINED(&l1_succ, sizeof(unsigned) );  // this is ok cause it's reject sampling
        #endif
        if( !l1_succ ) continue;
        gf256mat_back_substitute(r_l1_F1, mat_l1, _O);
        memcpy( x_o1 , r_l1_F1 , _O_BYTE );
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
        gf256v_add( r_l1_F1 , y , _O_BYTE );    // substract the contribution from vinegar variables

#if _GFSIZE == 256
        l1_succ = gf256mat_gaussian_elim(mat_l1 , r_l1_F1, _O);
        #if defined(_VALGRIND_)
        VALGRIND_MAKE_MEM_DEFINED(&l1_succ, sizeof(unsigned) );  // this is ok cause it's reject sampling
        #endif
        if( !l1_succ ) continue;
        gf256mat_back_substitute(r_l1_F1, mat_l1, _O);
        memcpy( x_o1 , r_l1_F1 , _O_BYTE );
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
    // identity part of T.
    memcpy( w , vinegar , _V_BYTE );
    memcpy( w + _V_BYTE , x_o1 , _O_BYTE );

    // Computing the t1 part.
    gfmat_prod(y, sk->t1, _V_BYTE , _O , x_o1 );
    gf256v_add(w, y, _V_BYTE );

    t1 = hal_get_time();
    printcycles("BENCH 5 :", t1-t0); 

#else

    //  w = T^-1 * x
    uint8_t * w = signature;   // [_PUB_N_BYTE];
    // identity part of T.
    memcpy( w , vinegar , _V_BYTE );
    memcpy( w + _V_BYTE , x_o1 , _O_BYTE );

    // Computing the t1 part.
    gfmat_prod(y, sk->t1, _V_BYTE , _O , x_o1 );
    gf256v_add(w, y, _V_BYTE );

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


