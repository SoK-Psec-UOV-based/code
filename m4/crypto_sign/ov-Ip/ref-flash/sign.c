///  @file  sign.c
///  @brief the implementations for functions in api.h
///
///
#include <stdlib.h>
#include <string.h>

#include "params.h"
#include "ov_keypair.h"
#include "ov_keypair_computation.h"
#include "ov.h"

#include "hal-flash.h"

#include "api.h"

#include "utils_prng.h"

#if defined(_UTILS_SUPERCOP_)
#include "crypto_sign.h"
#endif


int
crypto_sign_keypair(unsigned char *pk, unsigned char *sk)
{
    unsigned char sk_seed[LEN_SKSEED];
    unsigned char pk_seed[LEN_PKSEED];
    randombytes( sk_seed , LEN_SKSEED );
    randombytes( pk_seed , LEN_PKSEED );

#if defined _OV_CLASSIC
    int r = generate_keypair( (pk_t*) pk , (sk_t*) sk , pk_seed, sk_seed );
#elif defined _OV_PKC
    int r = generate_keypair_pkc( (cpk_t*) pk , (sk_t*) sk , pk_seed , sk_seed );
#elif defined _OV_PKC_SKC
    int r = generate_keypair_pkc_skc( (cpk_t*) pk , (csk_t*) sk , pk_seed , sk_seed );
#else
error here
#endif
    return r;
}

#ifdef KEYS_IN_FLASH
int
crypto_sign_keypair_sk(unsigned char *sk, unsigned char *pk_seed)
{
    unsigned char sk_seed[LEN_SKSEED] = {0};
    randombytes( sk_seed , LEN_SKSEED );
    randombytes(pk_seed , LEN_PKSEED);


#if defined _OV_CLASSIC
    generate_secretkey((sk_t *)sk, pk_seed, sk_seed);
#elif defined _OV_PKC

    expand_sk((sk_t *)sk, pk_seed, sk_seed);
#elif defined _OV_PKC_SKC
    csk_t *rsk = (csk_t *)sk;
    memcpy( rsk->pk_seed , pk_seed , LEN_PKSEED );
    memcpy( rsk->sk_seed , sk_seed , LEN_SKSEED );
#endif
    return 0;
}

#ifdef _OV_PKC_SKC
static void expand_sk_into_flash(csk_t *rsk)
{
    sk_t _sk;
    expand_sk(&_sk, rsk->pk_seed, rsk->sk_seed);
    write_tmp_to_flash((unsigned char *)&_sk);
}
#endif

int
crypto_sign_keypair_pk(unsigned char *pk, const unsigned char *sk, const unsigned char *pk_seed)
{
    #if defined _OV_CLASSIC
        return sk_to_pk((pk_t*) pk, (const sk_t *) sk, pk_seed);
    #elif defined _OV_PKC
        cpk_t *cpk = (cpk_t *)pk;
        memcpy(cpk->pk_seed, pk_seed, LEN_PKSEED);
        ov_pkc_calculate_Q_from_F((cpk_t *)pk,(sk_t *) sk, (sk_t *) sk);
        return 0;
    #elif defined _OV_PKC_SKC
        cpk_t *cpk = (cpk_t *)pk;
        csk_t *rsk = (csk_t *)sk;

        sk_t *sktmp = (sk_t *)get_tmp_flash();
        // expand secret key
        expand_sk_into_flash(rsk);
        memcpy(cpk->pk_seed, pk_seed, LEN_PKSEED);
        ov_pkc_calculate_Q_from_F((cpk_t *)pk, sktmp, sktmp);
        return 0;
    #endif
}
#endif





int
#if defined(PQM4)
crypto_sign(unsigned char *sm, size_t *smlen, const unsigned char *m, size_t mlen, const unsigned char *sk)
#else
crypto_sign(unsigned char *sm, unsigned long long *smlen, const unsigned char *m, unsigned long long mlen, const unsigned char *sk)
#endif
{
	int r = -1;
#if defined _OV_CLASSIC

	// r = ov_sign( sm + mlen , (const sk_t*)sk , m , mlen );
	r = ov_sign( sm + mlen , (sk_t*)sk , m , mlen );    

#elif defined _OV_PKC

	r = ov_sign( sm + mlen , (const sk_t*)sk , m , mlen );

#elif defined _OV_PKC_SKC

	r = ov_expand_and_sign( sm + mlen , (const csk_t*)sk , m , mlen );

#else
error here
#endif
	memcpy( sm , m , mlen );
	smlen[0] = mlen + OV_SIGNATUREBYTES;

	return r;
}






int
#if defined(PQM4)
crypto_sign_open(unsigned char *m, size_t *mlen,const unsigned char *sm, size_t smlen,const unsigned char *pk)
#else
crypto_sign_open(unsigned char *m, unsigned long long *mlen,const unsigned char *sm, unsigned long long smlen,const unsigned char *pk)
#endif
{
	if( OV_SIGNATUREBYTES > smlen ) return -1;
	unsigned long mesg_len = smlen-OV_SIGNATUREBYTES;
	int r = -1;

#if defined _OV_CLASSIC

	r = ov_verify( sm , mesg_len , sm + mesg_len , (const pk_t *)pk );

#elif defined _OV_PKC

	r = ov_expand_and_verify( sm , mesg_len , sm + mesg_len , (const cpk_t *)pk );

#elif defined _OV_PKC_SKC

	r = ov_expand_and_verify( sm , mesg_len , sm + mesg_len , (const cpk_t *)pk );

#else
error here
#endif

	memcpy( m , sm , mesg_len );
	mlen[0] = mesg_len;

	return r;
}

