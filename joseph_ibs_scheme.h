#ifndef JOSEPH_IBS_SCHEME_H
#define JOSEPH_IBS_SCHEME_H

#include <sys/types.h>

#include <openssl/bn.h>
#include <openssl/ec.h>




#define KEY_LENGTH_BITS 160

int hash_buffer(const u_char *, u_int, const EVP_MD *, u_char **, u_int *);
void debug3_bn(const BIGNUM *, const char *, ...)
    __attribute__((__nonnull__ (2)))
    __attribute__((format(printf, 2, 3)));
void debug3_buf(const u_char *, u_int, const char *, ...)
    __attribute__((__nonnull__ (3)))
    __attribute__((format(printf, 3, 4)));
struct modp_group *modp_group_from_g_p_and_q(const char *, const char *, const char *);
void modp_group_free(struct modp_group *);


///////////////////////////////////////////////////////////////////////////
//Public API for Joseph IBS scheme

/* System parameter setup */


int joseph_ibs_setup(EC_KEY **eckey);

/* Signature and verification functions */
int joseph_ibs_extract(const EC_KEY *key, const u_char *id, const u_int idlen,
    u_char **sig, u_int *siglen);

int joseph_ibs_offline_sign(const EC_KEY *key,const char path[]);

int
joseph_ibs_online_sign(const EC_KEY *key, BIGNUM *R_X, BIGNUM *R_Y, const BIGNUM *s,
                   const u_char *msg, const u_int msglen, const char path[],
                   u_char **sig, u_int *siglen);

int joseph_ibs_offline_verify(const EC_KEY *key,const char pathX[], const char pathY[]);

int joseph_ibs_online_verify( const EC_KEY *key, const char pathX[], const char pathY[],const u_char *id, u_int idlen,
                               const u_char *sig, u_int siglen, const u_char*msg, u_int msglen);


//The following functions return 1 on success or 0 on error:

int ternary_expansion_precompute(const EC_GROUP *group, EC_POINT *r, const BIGNUM *x_scalar, const EC_POINT *points[], BN_CTX *ctx);



//int joseph_ibs_verify_buf(const BIGNUM *grp_p, const BIGNUM *grp_q,
   // const BIGNUM *grp_g,
   // const BIGNUM *g_x, const u_char *id, u_int idlen,
   // const u_char *sig, u_int siglen, const u_char *msg, u_int msglen);
//////////////////////////////////////////////////////////////////////////////

#endif // JOSEPH_IBS_SCHEME_H
