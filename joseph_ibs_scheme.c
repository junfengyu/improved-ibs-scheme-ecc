#include <sys/types.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include "buffer.h"
#include "joseph_ibs_scheme.h"

#include "prof.h"


int joseph_ibs_setup(EC_KEY **eckey)
{
// (Group, order, Publickey, privatekey)

    int success = 1;


    if (((*eckey) = EC_KEY_new_by_curve_name(NID_secp160k1)) == NULL)
            goto out;
        if (!EC_KEY_generate_key((*eckey)))
            goto out;
    success = 0;

out:
    return success;

}



/*
 * Calculate hash  H(g^v ||  id)
 * using the hash function defined by "evp_md". Returns signature as
 * bignum or NULL on error.
 */

static BIGNUM *
extract_do_hash(const EVP_MD *evp_md, const BIGNUM *R_x, const BIGNUM *R_y, const u_char *id, u_int idlen)
{
    u_char *digest;
    u_int digest_len;
    BIGNUM *h;
    Buffer b;

    int success = -1;

    if ((h = BN_new()) == NULL) {
        return NULL;
    }


    buffer_init(&b);
    /*h =H(g^v||ID)*/

    buffer_put_bignum2(&b, R_x);

    buffer_put_bignum2(&b, R_y);

    buffer_put_string(&b, id, idlen);


    if (hash_buffer(buffer_ptr(&b), buffer_len(&b), evp_md,
        &digest, &digest_len) != 0) {

        goto out;
    }
    if (BN_bin2bn(digest, (int)digest_len, h) == NULL) {

        goto out;
    }
    success = 0;

 out:
    buffer_free(&b);
    bzero(digest, digest_len);
    xfree(digest);
    digest_len = 0;
    if (success == 0)
        return h;
    BN_clear_free(h);
    return NULL;
}

/*
 do extract work
 */
int
do_extract(const  EC_KEY *key, const EVP_MD *evp_md, const u_char *id, u_int idlen, BIGNUM **a_s, BIGNUM **a_R_x, BIGNUM **a_R_y, EC_POINT **a_R)
{
    int success = -1;
    BIGNUM *h, *tmp, *order=NULL;
    BN_CTX *ctx=NULL;
    EC_POINT *tmp_point=NULL, *R_point=NULL;

    BIGNUM *R_x,*R_y;
    BIGNUM *k = NULL, *s=NULL;
    EC_GROUP   *group;

    BIGNUM *x;

    group    = EC_KEY_get0_group(key);
    x = EC_KEY_get0_private_key(key);


    if (group == NULL || x == NULL)
        goto out;

    h = tmp = NULL;

    if ((ctx = BN_CTX_new()) == NULL || (tmp = BN_new()) == NULL)
        goto out;

    k     = BN_new();	// k is actually r in the paper

    order = BN_new();

    s     = BN_new();

    if (!k || !order || !s)
        goto out;

    if ((tmp_point = EC_POINT_new(group)) == NULL)
        goto out;

    if ((R_point = EC_POINT_new(group)) == NULL)
        goto out;

    if (!EC_GROUP_get_order(group, order, ctx))
        goto out;


            /* get random k */
    do
        if (!BN_rand_range(k, order))
                goto out;
    while (BN_is_zero(k));

    if (!EC_POINT_mul(group, R_point, k, NULL, NULL, ctx))
            goto out;



    if ((R_x = BN_new()) == NULL) {
        return NULL;
    }
    if ((R_y = BN_new()) == NULL) {
        return NULL;
    }


    if (!EC_POINT_get_affine_coordinates_GFp(group, R_point, R_x, R_y, NULL))
        goto out;

    /* h = H( R|| id) */
    if ((h = extract_do_hash(evp_md, R_x, R_y, id, idlen)) == NULL) {

        goto out;
    }

    /* s = k + xh mod q */
    if (BN_mod_mul(tmp, x, h, order, ctx) == -1) {

        goto out;
    }
    if (BN_mod_add(s, k, tmp, order, ctx) == -1) {

        goto out;
    }


    *a_R = R_point;
    *a_s = s;
    *a_R_x = R_x;
    *a_R_y = R_y;

//**********************************************************************************test:g^s=RX^H(R,ID)
   //equation (1) in joseph's paper

/*
    EC_POINT *tmp_point1=NULL,*tmp_point2=NULL,*tmp_point3=NULL,*g_s=NULL;


    if ((tmp_point1 = EC_POINT_new(group)) == NULL)
        goto out;
    if ((tmp_point2 = EC_POINT_new(group)) == NULL)
        goto out;
    if ((tmp_point3 = EC_POINT_new(group)) == NULL)
        goto out;

    if ((g_s = EC_POINT_new(group)) == NULL)
        goto out;

    if (!EC_POINT_mul(group, g_s, s, NULL, NULL, ctx))
        goto out;

    tmp_point1 = EC_KEY_get0_public_key(key);


    if (!EC_POINT_mul(group, tmp_point2, NULL, tmp_point1, h, ctx))
        goto out;

    if (!EC_POINT_add(group, tmp_point3, R_point, tmp_point2, ctx))
        goto out;

    int result= EC_POINT_cmp(group, g_s, tmp_point3, ctx);


    //compare g_s and tmp_point3;

*/
//************************************************************************Test

    success = 0;
 out:
    BN_CTX_free(ctx);
    if (h != NULL)
        BN_clear_free(h);
    if (k != NULL)
        BN_clear_free(k);
    if(tmp != NULL)
        BN_clear_free(tmp);
    if(order != NULL)
        BN_clear_free(order);


    return success;
}

/*
 * Generate a secret key for identity ID
 * On success, 0 is returned and *siglen bytes of signature are returned in
 * *sig (caller to free). Returns -1 on failure.
 */
int
joseph_ibs_extract(const EC_KEY *key, const u_char *id, const u_int idlen, u_char **sig, u_int *siglen)
{
    BIGNUM *s,*Rx,*Ry;
    EC_POINT *R;



    int success = 1;


    Buffer b;

    if (do_extract(key, EVP_sha1(), id, idlen, &s, &Rx, &Ry, &R) != 0)
        goto out;

    /* Signature is (R, s) */
    buffer_init(&b);
    /* XXX sigtype-hash as string */
    buffer_put_bignum2(&b, Rx);
    buffer_put_bignum2(&b, Ry);
    buffer_put_bignum2(&b, s);
    *siglen = buffer_len(&b);

    if(*siglen == 0)
        goto out;
    *sig = malloc(*siglen);
    if (sig == NULL)
        goto out;

    memcpy(*sig, buffer_ptr(&b), *siglen);
    success = 0;
    buffer_free(&b);
out:


    if (s!= NULL)
       BN_clear_free(s);
    if (Rx!= NULL)
       BN_clear_free(Rx);
    if (Ry!= NULL)
        BN_clear_free(Ry);
    if(R!=NULL)
        EC_POINT_free(R);
    return success;
}


/*
 *
 */

int joseph_ibs_offline_sign(const EC_KEY *key,const char path[])
{
// generate a binary file which will be distributed to each nodes
    int i;
    int success = 1;
    BIGNUM *exp_i = NULL;
    BN_CTX *bn_ctx= NULL;
    BIGNUM *big_2 = NULL;
    BIGNUM *big_i = NULL;

    PROF_START();
    BN_dec2bn(&big_2, "2");
    if ((bn_ctx = BN_CTX_new()) == NULL)
        goto out;

    EC_GROUP   *group=NULL;

    EC_POINT *tmp_point=NULL;

    BIGNUM *X, *Y, *Z;


    group    = EC_KEY_get0_group(key);
    if(group == NULL)
        goto out;


    if ((tmp_point = EC_POINT_new(group)) == NULL)
        goto out;

    if ((exp_i = BN_new()) == NULL ||(big_i = BN_new()) == NULL) {
        goto out;
    }

    Buffer b;
    buffer_init(&b);

    if ((X = BN_new()) == NULL) {
        return NULL;
    }
    if ((Y = BN_new()) == NULL) {
        return NULL;
    }

    for(i=0;i<KEY_LENGTH_BITS+1;i++)
    {
        BN_set_word(big_i, i);
        if (BN_exp(exp_i, big_2, big_i, bn_ctx) == -1)
           goto out;

       if (!EC_POINT_mul(group, tmp_point, exp_i, NULL, NULL, bn_ctx))
                goto out;



       if (!EC_POINT_get_affine_coordinates_GFp(group, tmp_point, X, Y, NULL))
           goto out;
       buffer_put_bignum(&b, X);
       buffer_put_bignum(&b, Y);
    }


    if(X!=NULL)
        BN_clear_free(X);
    if(Y!=NULL)
        BN_clear_free(Y);

    PROF_STDOUT();
    FILE* data;
    if ( (data = fopen(path, "wb")) == NULL )
    {
        goto out;
    }
    fwrite(b.buf, sizeof(u_char), b.end, data);
    fclose(data);
    success = 0;

out:


    buffer_free(&b);
    BN_CTX_free(bn_ctx);


    if (exp_i != NULL)
        BN_clear_free(exp_i);
    if (big_2 != NULL)
        BN_clear_free(big_2);
    if (big_i != NULL)
        BN_clear_free(big_i);

    if(tmp_point!=NULL)
        EC_POINT_free(tmp_point);
    return success;
}


/*
 * Calculate hash component of  H(Y || R || msg)
 * using the hash function defined by "evp_md". Returns signature as
 * bignum or NULL on error.
 */


static BIGNUM *
online_do_hash(const EVP_MD *evp_md, const BIGNUM *Y_X, const BIGNUM *Y_Y, const BIGNUM *R_X, const BIGNUM *R_Y,
    const u_char *msg, u_int msglen)
{
    u_char *digest;
    u_int digest_len;
    BIGNUM *h;
    Buffer b;
    int success = -1;

    if ((h = BN_new()) == NULL) {
       return NULL;
    }

    buffer_init(&b);
    /*h =H(Y||R||msg)*/
    buffer_put_bignum2(&b, Y_X);
    buffer_put_bignum2(&b, Y_Y);
    buffer_put_bignum2(&b, R_X);
    buffer_put_bignum2(&b, R_Y);
    buffer_put_string(&b, msg, msglen);
    if (hash_buffer(buffer_ptr(&b), buffer_len(&b), evp_md,
        &digest, &digest_len) != 0) {

        goto out;
    }
    if (BN_bin2bn(digest, (int)digest_len, h) == NULL) {

        goto out;
    }
    success = 0;

 out:
    buffer_free(&b);
    bzero(digest, digest_len);
    xfree(digest);
    digest_len = 0;
    if (success == 0)
        return h;
    BN_clear_free(h);
    return NULL;
}


int
joseph_ibs_online_sign(const EC_KEY *key, BIGNUM *R_X, BIGNUM *R_Y, const BIGNUM *s,
                   const u_char *msg, const u_int msglen, const char path[],
                   u_char **sig, u_int *siglen)
{
    int success = 1;

    BIGNUM *tmp_X,*tmp_Y;
    FILE *file;
    u_char *buffer;
    Buffer Y_buffer;
    buffer_init(&Y_buffer);
    tmp_X=BN_new();
    tmp_Y=BN_new();
    unsigned long fileLen;
    file=fopen(path,"rb");
    if(!file){
        return -1;
    }

    //Get file length
    fseek(file, 0, SEEK_END);
    fileLen=ftell(file);
    fseek(file, 0, SEEK_SET);

    if(fileLen==0)
        goto out;
    //Allocate memory
    buffer=(u_char *)malloc(fileLen+1);
    if (!buffer)
    {

        fclose(file);
        return -1;
    }


    //Read file contents into buffer
    fread(buffer, fileLen, 1, file);
    fclose(file);

    buffer_append(&Y_buffer, buffer, fileLen);
    free(buffer);

    BIGNUM *BN_Array_X[KEY_LENGTH_BITS+1];
    BIGNUM *BN_Array_Y[KEY_LENGTH_BITS+1];
    int i;
    for(i=0;i<KEY_LENGTH_BITS+1;i++)
    {
        buffer_get_bignum(&Y_buffer,tmp_X);
        buffer_get_bignum(&Y_buffer,tmp_Y);
        BN_Array_X[i]=tmp_X;
        BN_Array_Y[i]=tmp_Y;
        tmp_X=BN_new();
        tmp_Y=BN_new();
    }
    buffer_free(&Y_buffer);
    //retrieve offline signature
    ////////////////////////////////////////////////////////////////////////////////////
    /// \brief y_random
    ///
    ///
    ///
    PROF_START();
    BIGNUM *y_random = NULL;
    EC_GROUP *group = NULL;

    BN_CTX *bn_ctx;
    BIGNUM  *order=NULL;
    group = EC_KEY_get0_group(key);

    bn_ctx = BN_CTX_new();

    order = BN_new();
    if (!EC_GROUP_get_order(group, order, bn_ctx))
        goto out;
    y_random=BN_new();
    /* get random k */
    do
    if (!BN_rand_range(y_random, order))
        goto out;
    while (BN_is_zero(y_random));


    EC_POINT *tmp_point=NULL;
    BIGNUM *Y_X, *Y_Y;

    tmp_Y = BN_new();
    tmp_X = BN_new();
    Y_Y = BN_new();
    Y_X = BN_new();

    //compute Y
    /////////////////////////////////////////////////////////////////////////////////////////

    EC_POINT *POINTs[KEY_LENGTH_BITS+1];

    EC_POINT *r=NULL;
    if ((r = EC_POINT_new(group)) == NULL)
        goto out;

    for (i=0;i<KEY_LENGTH_BITS+1;i++)
    {
        tmp_X = BN_Array_X[i];
        tmp_Y = BN_Array_Y[i];


        if ((tmp_point = EC_POINT_new(group)) == NULL)
            goto out;


        if (!EC_POINT_set_affine_coordinates_GFp(group, tmp_point, tmp_X, tmp_Y, NULL))
                goto out;

        POINTs[i] = tmp_point;
    }
    if(ternary_expansion_precompute(group, r, y_random, POINTs, bn_ctx)==0)
        goto out;

    if (!EC_POINT_get_affine_coordinates_GFp(group, r, Y_X, Y_Y, NULL))
            goto out;

    /////////////////////////////////////////////////////////////////////////////////////////

    BIGNUM *h, *z;
    BIGNUM *tmp = NULL;
    z=h=NULL;
    z=BN_new();
    tmp = BN_new();
    h=online_do_hash(EVP_sha1(), Y_X, Y_Y, R_X, R_Y, msg, msglen);


    /* z = y+ hs mod q */
    if (BN_mod_mul(tmp, h, s, order, bn_ctx) == -1) {

        goto out;
    }
    if (BN_mod_add(z, y_random, tmp, order, bn_ctx) == -1) {

        goto out;
    }

    Buffer b;
    /* Signature is (Y, R,z) */
      buffer_init(&b);
        /* XXX sigtype-hash as string */
    buffer_put_bignum2(&b, Y_X);
    buffer_put_bignum2(&b, Y_Y);
    buffer_put_bignum2(&b, R_X);
    buffer_put_bignum2(&b, R_Y);
    buffer_put_bignum2(&b, z);


    *siglen = buffer_len(&b);

    if(*siglen == 0)
        goto out;
    *sig = malloc(*siglen);
    if (sig == NULL)
        goto out;

    memcpy(*sig, buffer_ptr(&b), *siglen);

    buffer_free(&b);


    success = 0;
out:
    BN_CTX_free(bn_ctx);

    if (h != NULL)
        BN_clear_free(h);
    if (z!= NULL)
        BN_clear_free(z);
    if(y_random!=NULL)
        BN_clear_free(y_random);

    if(order!=NULL)
        BN_clear_free(order);


    if(Y_X!=NULL)
        BN_clear_free(Y_X);
    if(Y_Y!=NULL)
        BN_clear_free(Y_Y);

    if(tmp!=NULL)
        BN_clear_free(tmp);

    if(tmp_point!=NULL)
        EC_POINT_free(tmp_point);

    if(r!=NULL)
        EC_POINT_free(r);

    for(i=0;i<KEY_LENGTH_BITS+1;i++)
    {
        if(BN_Array_X[i]!=NULL)
            BN_clear_free(BN_Array_X[i]);
        if(BN_Array_Y[i]!=NULL)
            BN_clear_free(BN_Array_Y[i]);

    }
    PROF_STDOUT();
    return success;

}






int joseph_ibs_offline_verify(const EC_KEY *key,const char pathX[], const char pathY[])
{
// generate a binary file which will be distributed to each nodes
    int i;
    int success = 1;
    BIGNUM *exp_i = NULL;
    BN_CTX *bn_ctx= NULL;
    BIGNUM *big_2 = NULL;
    BIGNUM *big_i = NULL;

    PROF_START();
    BN_dec2bn(&big_2, "2");
    if ((bn_ctx = BN_CTX_new()) == NULL)
        goto out;

    EC_GROUP   *group=NULL;

    EC_POINT *tmp_point1=NULL,*tmp_point2=NULL,*PublicKey=NULL;

    BIGNUM *X, *Y;


    group    = EC_KEY_get0_group(key);
    if(group == NULL)
        goto out;

    if ((PublicKey= EC_POINT_new(group)) == NULL)
           goto out;

    PublicKey = EC_KEY_get0_public_key(key);


    if ((tmp_point1 = EC_POINT_new(group)) == NULL)
        goto out;
    if ((tmp_point2 = EC_POINT_new(group)) == NULL)
        goto out;

    if ((exp_i = BN_new()) == NULL ||(big_i = BN_new()) == NULL) {
        goto out;
    }

    Buffer b,c;
    buffer_init(&b);
    buffer_init(&c);

    if ((X = BN_new()) == NULL) {
        return NULL;
    }
    if ((Y = BN_new()) == NULL) {
        return NULL;
    }

    for(i=0;i<KEY_LENGTH_BITS+1;i++)
    {
        BN_set_word(big_i, i);
        if (BN_exp(exp_i, big_2, big_i, bn_ctx) == -1)
           goto out;

       if (!EC_POINT_mul(group, tmp_point1, NULL, PublicKey,exp_i, bn_ctx))
                goto out;
       if (!EC_POINT_mul(group, tmp_point2, exp_i, NULL, NULL, bn_ctx))
                goto out;

       if (!EC_POINT_get_affine_coordinates_GFp(group, tmp_point1, X, Y, NULL))
           goto out;
       buffer_put_bignum(&b, X);
       buffer_put_bignum(&b, Y);

       if (!EC_POINT_get_affine_coordinates_GFp(group, tmp_point2, X, Y, NULL))
           goto out;
       buffer_put_bignum(&c, X);
       buffer_put_bignum(&c, Y);

    }

    PROF_STDOUT();
    FILE* data;
    if ( (data = fopen(pathX, "wb")) == NULL )
    {
        goto out;
    }
    fwrite(b.buf, sizeof(u_char), b.end, data);
    fclose(data);

    if ( (data = fopen(pathY, "wb")) == NULL )
    {
        goto out;
    }
    fwrite(c.buf, sizeof(u_char), c.end, data);
    fclose(data);

    success = 0;

out:

    buffer_free(&b);
    buffer_free(&c);
    BN_CTX_free(bn_ctx);


    if(tmp_point1!=NULL)
        EC_POINT_free(tmp_point1);
    if(tmp_point2!=NULL)
        EC_POINT_free(tmp_point2);
    if(PublicKey!=NULL)
        EC_POINT_free(PublicKey);

    if ( X != NULL)
        BN_clear_free(X);
    if ( Y!= NULL)
        BN_clear_free(Y);
    if (exp_i != NULL)
        BN_clear_free(exp_i);
    if (big_2 != NULL)
        BN_clear_free(big_2);
    if (big_i != NULL)
        BN_clear_free(big_i);


    return success;
}



//-----------------------------------------------------------------------------------------------------------------------------------------------------------------

/*
 * Calculate hash component of  H(Y || R || msg)
 * using the hash function defined by "evp_md". Returns signature as
 * bignum or NULL on error.
 */

static BIGNUM *
verify_do_hash(const EVP_MD *evp_md, const BIGNUM *Y_X, const BIGNUM *Y_Y, const BIGNUM *R_X, const BIGNUM *R_Y,
    const u_char *msg, u_int msglen)
{
    u_char *digest;
    u_int digest_len;
    BIGNUM *h;
    Buffer b;
    int success = -1;

    if ((h = BN_new()) == NULL) {
       return NULL;
    }

    buffer_init(&b);
    /*h =H(Y||R||msg)*/
    buffer_put_bignum2(&b, Y_X);
    buffer_put_bignum2(&b, Y_Y);
    buffer_put_bignum2(&b, R_X);
    buffer_put_bignum2(&b, R_Y);
    buffer_put_string(&b, msg, msglen);
    if (hash_buffer(buffer_ptr(&b), buffer_len(&b), evp_md,
        &digest, &digest_len) != 0) {

        goto out;
    }
    if (BN_bin2bn(digest, (int)digest_len, h) == NULL) {

        goto out;
    }
    success = 0;

 out:
    buffer_free(&b);
    bzero(digest, digest_len);
    xfree(digest);
    digest_len = 0;
    if (success == 0)
        return h;
    BN_clear_free(h);
    return NULL;
}

/*
 * Calculate hash component of  H(R || id)
 * using the hash function defined by "evp_md". Returns signature as
 * bignum or NULL on error.
 */

static BIGNUM *
verify_do_hash_RID(const EVP_MD *evp_md, const BIGNUM *R_X, const BIGNUM *R_Y, const u_char *id, u_int idlen)
{
    u_char *digest;
    u_int digest_len;
    BIGNUM *h;
    Buffer b;
    int success = -1;

    if ((h = BN_new()) == NULL) {
        return NULL;
    }

    buffer_init(&b);
    /*h =H(R||ID)*/

    buffer_put_bignum2(&b, R_X);
    buffer_put_bignum2(&b, R_Y);

    buffer_put_string(&b, id, idlen);


    if (hash_buffer(buffer_ptr(&b), buffer_len(&b), evp_md,
        &digest, &digest_len) != 0) {

        goto out;
    }
    if (BN_bin2bn(digest, (int)digest_len, h) == NULL) {

        goto out;
    }
    success = 0;

 out:
    buffer_free(&b);
    bzero(digest, digest_len);
    xfree(digest);
    digest_len = 0;
    if (success == 0)
        return h;
    BN_clear_free(h);
    return NULL;
}
//------------------------------------------------------------------------------------------------------

int joseph_ibs_online_verify( const EC_KEY *key, const char pathX[], const char pathY[], const u_char *id, u_int idlen,
                               const u_char *sig, u_int siglen, const u_char*msg, u_int msglen)
{
    int success = -1;
    BIGNUM *tmp_X,*tmp_Y;
    FILE *file;
    u_char *buffer;
    Buffer X_buffer,Y_buffer;
    buffer_init(&X_buffer);

    tmp_X=BN_new();
    tmp_Y=BN_new();
    unsigned long fileLen;

    file=fopen(pathX,"rb");
        if(!file){
            return -1;
    }

        //Get file length
    fseek(file, 0, SEEK_END);
    fileLen=ftell(file);
    fseek(file, 0, SEEK_SET);

    if(fileLen==0)
        goto out;
        //Allocate memory
    buffer=(u_char *)malloc(fileLen+1);
    if (!buffer)
    {

        fclose(file);
        return -1;
    }

        //Read file contents into buffer
    fread(buffer, fileLen, 1, file);
    fclose(file);

    buffer_append(&X_buffer, buffer, fileLen);
    free(buffer);
    //-----------------------------------------------

    buffer_init(&Y_buffer);

    file=fopen(pathY,"rb");
        if(!file){
            return -1;
    }

        //Get file length
    fseek(file, 0, SEEK_END);
    fileLen=ftell(file);
    fseek(file, 0, SEEK_SET);

    if(fileLen==0)
        goto out;
        //Allocate memory
    buffer=(u_char *)malloc(fileLen+1);
    if (!buffer)
    {

        fclose(file);
        return -1;
    }

        //Read file contents into buffer
    fread(buffer, fileLen, 1, file);
    fclose(file);

    buffer_append(&Y_buffer, buffer, fileLen);
    free(buffer);

    BIGNUM *BN_X_Array_X[KEY_LENGTH_BITS+1];
    BIGNUM *BN_X_Array_Y[KEY_LENGTH_BITS+1];
    int i;
    for(i=0;i<KEY_LENGTH_BITS+1;i++)
    {
        buffer_get_bignum(&X_buffer,tmp_X);
        buffer_get_bignum(&X_buffer,tmp_Y);
        BN_X_Array_X[i]=tmp_X;
        BN_X_Array_Y[i]=tmp_Y;
        tmp_X=BN_new();
        tmp_Y=BN_new();
    }
    buffer_free(&X_buffer);


    BIGNUM *BN_Y_Array_X[KEY_LENGTH_BITS+1];
    BIGNUM *BN_Y_Array_Y[KEY_LENGTH_BITS+1];
    for(i=0;i<KEY_LENGTH_BITS+1;i++)
    {
        buffer_get_bignum(&Y_buffer,tmp_X);
        buffer_get_bignum(&Y_buffer,tmp_Y);
        BN_Y_Array_X[i]=tmp_X;
        BN_Y_Array_Y[i]=tmp_Y;
        tmp_X=BN_new();
        tmp_Y=BN_new();
    }
    buffer_free(&Y_buffer);




    Buffer b;

    u_int rlen;
    BIGNUM *Y_X=NULL, *Y_Y=NULL,*R_X=NULL,*R_Y=NULL, *z=NULL;
    BN_CTX *bn_ctx;


    if ((Y_X = BN_new()) == NULL ||
        (Y_Y = BN_new()) == NULL ||
        (R_X = BN_new()) == NULL ||
        (R_Y = BN_new()) == NULL ||
        (z = BN_new()) == NULL)
    {
        goto out;
    }

    if ((bn_ctx = BN_CTX_new()) == NULL) {
        goto out;
    }

    /* Extract Y, R and z from signature */
    buffer_init(&b);
    buffer_append(&b, sig, siglen);

    buffer_get_bignum2(&b, Y_X);
    buffer_get_bignum2(&b, Y_Y);
    buffer_get_bignum2(&b, R_X);
     buffer_get_bignum2(&b, R_Y);
    buffer_get_bignum2(&b, z);
    rlen = buffer_len(&b);
    buffer_free(&b);
    if (rlen != 0) {
        goto out;
    }

    PROF_START();

    BIGNUM *h_RYM, *h_RID, *h;

    EC_POINT *R=NULL, *Y=NULL;

    EC_GROUP *group = NULL;

    BIGNUM  *order=NULL;

    group = EC_KEY_get0_group(key);


    order = BN_new();
    if (!EC_GROUP_get_order(group, order, bn_ctx))
        goto out;


    if ((R = EC_POINT_new(group)) == NULL)
        goto out;
    if ((Y = EC_POINT_new(group)) == NULL)
        goto out;

    if (!EC_POINT_set_affine_coordinates_GFp(group, R, R_X, R_Y, NULL))
            goto out;

    if (!EC_POINT_set_affine_coordinates_GFp(group, Y, Y_X, Y_Y, NULL))
            goto out;

    h = h_RYM = h_RID = NULL;
    if ((bn_ctx = BN_CTX_new()) == NULL) {
        goto out;
    }
    if ((h_RID = BN_new()) == NULL ||
        (h = BN_new()) == NULL ||
        (h_RYM = BN_new()) == NULL){
        goto out;
    }


    /* h = H(Y|| R || m) */
    if ((h_RYM = verify_do_hash(EVP_sha1(), Y_X, Y_Y, R_X, R_Y, msg, msglen)) == NULL) {

        goto out;
    }
    /* h_RID = H(R || ID) */
    if ((h_RID = verify_do_hash_RID(EVP_sha1(), R_X, R_Y, id, idlen)) == NULL) {

        goto out;
    }


    if(BN_mod_mul(h, h_RYM, h_RID, order, bn_ctx) == -1)
    {
       goto out;

    }


    tmp_Y = BN_new();
    tmp_X = BN_new();

    //compute Z^ sum

    /////////////////////////////////////////////////////////////////////////////////////////

    EC_POINT *z_POINTs[KEY_LENGTH_BITS+1];

    EC_POINT *Z_= NULL, *ternary_tmp_point = NULL;
    if ((Z_ = EC_POINT_new(group)) == NULL)
        goto out;


    if ((ternary_tmp_point = EC_POINT_new(group)) == NULL)
        goto out;

    for (i=0;i<KEY_LENGTH_BITS+1;i++)
    {

        tmp_X = BN_Y_Array_X[i];
        tmp_Y = BN_Y_Array_Y[i];

        if ((ternary_tmp_point = EC_POINT_new(group)) == NULL)
            goto out;


        if (!EC_POINT_set_affine_coordinates_GFp(group, ternary_tmp_point, tmp_X, tmp_Y, NULL))
                goto out;

        z_POINTs[i] = ternary_tmp_point;
    }
    if(ternary_expansion_precompute(group, Z_, z, z_POINTs, bn_ctx)==0)
        goto out;


    /////////////////////////////////////////////////////////////////////////////////////////





    /////////////////////////////////////////////////////////////////////////////////////////

/*
     EC_POINT *H_sum_add;
     if ((H_sum_add = EC_POINT_new(group)) == NULL)
         goto out;
     EC_POINT_set_to_infinity(group, H_sum_add);


     for (i=0;i<KEY_LENGTH_BITS+1;i++)
     {
         tmp_X = BN_X_Array_X[i];
         tmp_Y = BN_X_Array_Y[i];
         if (!EC_POINT_set_affine_coordinates_GFp(group, sum_tmp_point, tmp_X, tmp_Y, NULL))
                 goto out;

         if(BN_is_bit_set(h,i)==1)
             EC_POINT_add(group, H_sum_add, H_sum_add, sum_tmp_point, bn_ctx);
      }
*/

     //compute H^ sum


     /////////////////////////////////////////////////////////////////////////////////////////

     EC_POINT *h_POINTs[KEY_LENGTH_BITS+1];

     EC_POINT *H_= NULL;
     if ((H_ = EC_POINT_new(group)) == NULL)
         goto out;


     for (i=0;i<KEY_LENGTH_BITS+1;i++)
     {

         tmp_X = BN_X_Array_X[i];
         tmp_Y = BN_X_Array_Y[i];

         if ((ternary_tmp_point = EC_POINT_new(group)) == NULL)
             goto out;


         if (!EC_POINT_set_affine_coordinates_GFp(group, ternary_tmp_point, tmp_X, tmp_Y, NULL))
                 goto out;

         h_POINTs[i] = ternary_tmp_point;
     }
     if(ternary_expansion_precompute(group, H_, h, h_POINTs, bn_ctx)==0)
         goto out;


     /////////////////////////////////////////////////////////////////////////////////////////




     /////////////////////////////////////////////////////////////////////////////////////////

     EC_POINT *tmp_point1=NULL,*tmp_point2=NULL,*tmp_point_expected=NULL;


     if ((tmp_point1 = EC_POINT_new(group)) == NULL)
             goto out;
     if ((tmp_point2 = EC_POINT_new(group)) == NULL)
             goto out;
     if ((tmp_point_expected = EC_POINT_new(group)) == NULL)
             goto out;

     if (!EC_POINT_add(group, tmp_point1, Y, H_, bn_ctx))
            goto out;

     if (!EC_POINT_mul(group, tmp_point2, NULL, R, h_RYM, bn_ctx))
           goto out;



     if (!EC_POINT_add(group, tmp_point_expected, tmp_point1, tmp_point2, bn_ctx))
            goto out;


     success = EC_POINT_cmp(group, Z_, tmp_point_expected, bn_ctx);

out:


      EC_POINT_free(tmp_point1);
      EC_POINT_free(tmp_point2);
      EC_POINT_free(tmp_point_expected);
      EC_POINT_free(H_);
      EC_POINT_free(Z_);
      EC_POINT_free(ternary_tmp_point);

      EC_POINT_free(R);
      EC_POINT_free(Y);

      BN_CTX_free(bn_ctx);



      for(i=0;i<KEY_LENGTH_BITS+1;i++)
      {
          if(BN_X_Array_X[i]!=NULL)
              BN_clear_free(BN_X_Array_X[i]);
          if(BN_X_Array_Y[i]!=NULL)
              BN_clear_free(BN_X_Array_Y[i]);

      }

      for(i=0;i<KEY_LENGTH_BITS+1;i++)
      {
          if(BN_Y_Array_X[i]!=NULL)
              BN_clear_free(BN_Y_Array_X[i]);
          if(BN_Y_Array_Y[i]!=NULL)
              BN_clear_free(BN_Y_Array_Y[i]);

      }

    /* for(i=0;i<KEY_LENGTH_BITS+1;i++)
      {
          if(z_POINTs[i]!=NULL)
              EC_POINT_free(z_POINTs[i]);

          if(h_POINTs[i]!=NULL)
              EC_POINT_free(h_POINTs[i]);
      }
*/

      if (h_RYM != NULL)
          BN_clear_free(h_RYM);
      if (h_RID != NULL)
          BN_clear_free(h_RID);
      if (h != NULL)
          BN_clear_free(h);
      if (Y_X!= NULL)
          BN_clear_free(Y_X);
      if (Y_Y!= NULL)
          BN_clear_free(Y_Y);
      if (R_X!= NULL)
          BN_clear_free(R_X);
      if (R_Y!= NULL)
          BN_clear_free(R_Y);
      if (z= NULL)
          BN_clear_free(z);
      if (order!= NULL)
          BN_clear_free(order);

      PROF_STDOUT();
     return success;

}


//return 1 on success or 0 on error:
int ternary_expansion_precompute(const EC_GROUP *group, EC_POINT *res, const BIGNUM *x_scalar, const EC_POINT *points[], BN_CTX *ctx)
{

    BN_CTX *new_ctx = NULL;
    int ret = 0;
    int bits = BN_num_bits(x_scalar);

    int seq_ones = 0;
    EC_POINT  *inv_tmp = NULL;
    int i = 0;

    if(group == NULL)
        goto err;
    if (ctx == NULL)
    {
        ctx = new_ctx = BN_CTX_new();
        if (ctx == NULL)
            goto err;
    }


    if ((inv_tmp = EC_POINT_new(group)) == NULL) goto err;

    if (!EC_POINT_copy(inv_tmp, points[1])) goto err;

    if (!EC_POINT_invert(group, inv_tmp, ctx)) goto err;

    if (!EC_POINT_add(group, res, points[1], inv_tmp, ctx))
                    goto err;


    for (i=0;i<=bits-2;i++)
    {

        if (seq_ones){
            if((!BN_is_bit_set(x_scalar,i))&&(!BN_is_bit_set(x_scalar,i+1))){
                if (!EC_POINT_add(group, res, res, points[i], ctx))
                                goto err;
                seq_ones = 0;
            }else if (!BN_is_bit_set(x_scalar,i)){
                if (!EC_POINT_copy(inv_tmp, points[i])) goto err;
                if (!EC_POINT_invert(group, inv_tmp, ctx)) goto err;
                if (!EC_POINT_add(group, res, res, inv_tmp, ctx))
                                goto err;

            }
        }else{
            if((BN_is_bit_set(x_scalar,i))&&(BN_is_bit_set(x_scalar,i+1))){
                if (!EC_POINT_copy(inv_tmp, points[i])) goto err;
                if (!EC_POINT_invert(group, inv_tmp, ctx)) goto err;
                if (!EC_POINT_add(group, res, res, inv_tmp, ctx))
                                goto err;
                seq_ones = 1;
            }else if (BN_is_bit_set(x_scalar,i)){



                if (!EC_POINT_add(group, res, res, points[i], ctx))
                                goto err;
            }
        }


    }
    if (seq_ones){
        if (!EC_POINT_add(group, res, res, points[i+1], ctx))
                        goto err;
    }else
        if (!EC_POINT_add(group, res, res, points[i], ctx))
                        goto err;

    ret=1;
err:

    return ret;
}




//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/*
 * do verify signature
 * Returns -1 on failure, 0 on incorrect signature or 1 on matching signature.
 */

//do_verify(key, EVP_sha1(), id, idlen, msg, msglen, Y_X, Y_Y, R_X, R_Y, z);

int
do_verify(const EC_KEY *key,
    const EVP_MD *evp_md, const u_char *id, u_int idlen, const u_char *msg, u_int msglen,
    const BIGNUM *Y_X, const BIGNUM *Y_Y, const BIGNUM *R_X, const BIGNUM *R_Y, const BIGNUM *z)
{
    int success = -1;
    BIGNUM *h, *h_RID, *g_xhh, *hh, *R_h;
    BIGNUM *expected = NULL;
    BN_CTX *bn_ctx;

    EC_POINT *R=NULL, *Y=NULL;

    EC_GROUP *group = NULL;
    EC_POINT *PublicKey = NULL;
    BIGNUM  *order=NULL;

    group = EC_KEY_get0_group(key);

    bn_ctx = BN_CTX_new();

    order = BN_new();
    if (!EC_GROUP_get_order(group, order, bn_ctx))
        goto out;
    if ((PublicKey= EC_POINT_new(group)) == NULL)
           goto out;

    PublicKey = EC_KEY_get0_public_key(key);

    if ((R = EC_POINT_new(group)) == NULL)
        goto out;
    if ((Y = EC_POINT_new(group)) == NULL)
        goto out;

    if (!EC_POINT_set_affine_coordinates_GFp(group, R, R_X, R_Y, NULL))
            goto out;

    if (!EC_POINT_set_affine_coordinates_GFp(group, Y, Y_X, Y_Y, NULL))
            goto out;

    hh = h = h_RID = g_xhh = R_h = NULL;
    if ((bn_ctx = BN_CTX_new()) == NULL) {
        goto out;
    }
    if ((g_xhh = BN_new()) == NULL ||
        (hh = BN_new()) == NULL ||
        (R_h =BN_new()) == NULL ){
        goto out;
    }


    /* h = H(Y|| R || m) */
    if ((h = verify_do_hash(EVP_sha1(), Y_X, Y_Y, R_X, R_Y, msg, msglen)) == NULL) {

        goto out;
    }
    /* h_RID = H(R || ID) */
    if ((h_RID = verify_do_hash_RID(EVP_sha1(), R_X, R_Y, id, idlen)) == NULL) {

        goto out;
    }

    if(BN_mod_mul(hh, h, h_RID, order, bn_ctx) == -1)
    {
       goto out;

    }

    EC_POINT *tmp_point1=NULL,*tmp_point2=NULL,*tmp_point3=NULL,*tmp_point4=NULL,*tmp_point5=NULL,*tmp_point_expected=NULL,*g_z=NULL;


    if ((tmp_point1 = EC_POINT_new(group)) == NULL)
        goto out;
    if ((tmp_point2 = EC_POINT_new(group)) == NULL)
        goto out;
    if ((tmp_point3 = EC_POINT_new(group)) == NULL)
        goto out;
    if ((tmp_point4 = EC_POINT_new(group)) == NULL)
        goto out;
    if ((tmp_point5 = EC_POINT_new(group)) == NULL)
        goto out;
    if ((tmp_point_expected = EC_POINT_new(group)) == NULL)
        goto out;
    if ((g_z = EC_POINT_new(group)) == NULL)
        goto out;

    if (!EC_POINT_mul(group, tmp_point3, NULL, PublicKey, hh, bn_ctx))
        goto out;



    if (!EC_POINT_mul(group, tmp_point4, NULL, R, h, bn_ctx))
          goto out;
//tmp_point4 R^h
    if (!EC_POINT_add(group, tmp_point5, Y, tmp_point4, bn_ctx))
        goto out;

    if (!EC_POINT_add(group, tmp_point_expected, tmp_point5, tmp_point3, bn_ctx))
        goto out;

//tmp_point expected is the right part in the equation (2)
    /* expected = g^r * R^h * g_xhh */


    /* g_z = g^z */

    if (!EC_POINT_mul(group, g_z, z, NULL, NULL, bn_ctx))
        goto out;

    /* Check g_z == expected */
    success = EC_POINT_cmp(group, g_z, tmp_point_expected, bn_ctx);

 out:
    BN_CTX_free(bn_ctx);
    if (h != NULL)
        BN_clear_free(h);
    if (g_xhh!= NULL)
        BN_clear_free(g_xhh);

    if (hh != NULL)
        BN_clear_free(hh);
    if (R_h != NULL)
        BN_clear_free(R_h);
    if (h_RID != NULL)
        BN_clear_free(h_RID);
    if (expected != NULL)
        BN_clear_free(expected);
    return success;
}





/*
 * Verify signature 'sig' of length 'siglen'
 * Returns -1 on failure, 0 on incorrect signature or 1 on matching signature.
 */
int
joseph_ibs_verify_buf(const EC_KEY *key, const u_char *id, u_int idlen,
    const u_char *sig, u_int siglen, const u_char *msg, u_int msglen)
{
    Buffer b;
    int ret = -1;
    u_int rlen;
    BIGNUM *Y_X=NULL, *Y_Y=NULL,*R_X=NULL,*R_Y=NULL, *z=NULL;
    BN_CTX *bn_ctx;


    if ((Y_X = BN_new()) == NULL ||
        (Y_Y = BN_new()) == NULL ||
        (R_X = BN_new()) == NULL ||
        (R_Y = BN_new()) == NULL ||
        (z = BN_new()) == NULL)
    {
        goto out;
    }

    if ((bn_ctx = BN_CTX_new()) == NULL) {
        goto out;
    }

    /* Extract Y, R and z from signature */
    buffer_init(&b);
    buffer_append(&b, sig, siglen);

    buffer_get_bignum2(&b, Y_X);
    buffer_get_bignum2(&b, Y_Y);
    buffer_get_bignum2(&b, R_X);
     buffer_get_bignum2(&b, R_Y);
    buffer_get_bignum2(&b, z);
    rlen = buffer_len(&b);
    buffer_free(&b);
    if (rlen != 0) {
        goto out;
    }


    ret = do_verify(key, EVP_sha1(), id, idlen, msg, msglen, Y_X, Y_Y, R_X, R_Y, z);
 out:
    if(Y_X != NULL)
        BN_clear_free(Y_X);
    if(R_X != NULL)
        BN_clear_free(R_X);
    if(z !=NULL)
        BN_clear_free(z);

    return ret;
}

/* Helper functions */

/*
 * Generate uniformly distributed random number in range (1, high).
 * Return number on success, NULL on failure.
 */
/*

/*
 * Hash contents of buffer 'b' with hash 'md'. Returns 0 on success,
 * with digest via 'digestp' (caller to free) and length via 'lenp'.
 * Returns -1 on failure.
 */
int
hash_buffer(const u_char *buf, u_int len, const EVP_MD *md,
    u_char **digestp, u_int *lenp)
{
    u_char digest[EVP_MAX_MD_SIZE];
    u_int digest_len;
    EVP_MD_CTX evp_md_ctx;
    int success = -1;

    EVP_MD_CTX_init(&evp_md_ctx);

    if (EVP_DigestInit_ex(&evp_md_ctx, md, NULL) != 1) {

        goto out;
    }
    if (EVP_DigestUpdate(&evp_md_ctx, buf, len) != 1) {

        goto out;
    }
    if (EVP_DigestFinal_ex(&evp_md_ctx, digest, &digest_len) != 1) {

        goto out;
    }

    if(digest_len == 0)
        goto out;
    *digestp = malloc(digest_len);
    if (digestp == NULL)
        goto out;
    *lenp = digest_len;
    memcpy(*digestp, digest, *lenp);
    success = 0;
 out:
    EVP_MD_CTX_cleanup(&evp_md_ctx);
    bzero(digest, sizeof(digest));
    digest_len = 0;
    return success;
}


