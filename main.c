#include <stdio.h>

#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include "joseph_ibs_scheme.h"
#include "log.h"
#include "buffer.h"
//#include "prof.h"


int
main(int argc, char **argv)
{
    EC_KEY    *key = NULL;
    u_char *secretkey,*sig;
    u_int secretkey_len, siglen;

    //PROF_START();
    int sizeofulong=sizeof(BN_ULONG);
    printf("size of ulong is %d in your device.\n",sizeofulong);
    int sizeofint = sizeof(int);
    printf("size of int is %d in your device.\n",sizeofint);
//////////////////////////////////////////////////////////////////////////////////////////////////
//  //PKG: PKG  generate secret key and offline signature for each node
    joseph_ibs_setup(&key);

    joseph_ibs_extract(key,"10.0.0.1", 8, &secretkey, &secretkey_len);
//////////////////////////////////////////////////////////////////////////////////////////////////
// Offline signer:
    joseph_ibs_offline_sign(key,"data.bin"); //store offline signature in data.bin


//////////////////////////////////////////////////////////////////////////////////////////////////
// Signer:
   BIGNUM *R_X,*R_Y, *s;
    R_X = R_Y = s = NULL;
    R_X = BN_new();
    R_Y = BN_new();
    s = BN_new();
    Buffer b;
    int rlen=0;

    /* Extract g^v and s  */
    buffer_init(&b);
    buffer_append(&b, secretkey, secretkey_len);
    buffer_get_bignum2(&b, R_X);
    buffer_get_bignum2(&b, R_Y);
    buffer_get_bignum2(&b, s);
    rlen = buffer_len(&b);
    buffer_free(&b);

    if (rlen != 0)
        return -1;

    joseph_ibs_online_sign(key, R_X, R_Y, s, "hello world!", 12 ,"data.bin",
                       &sig, &siglen);
//////////////////////////////////////////////////////////////////////////////////////////////////


//verifier:
/*
    int ret=joseph_ibs_verify_buf(key, "10.0.0.1", 8, sig, siglen,
                          "hello world!", 12);
    if(ret==0)  // should be successful
       printf("1:verification result correct!\n");
    else
       printf("1:Failed!\n");

    ret=joseph_ibs_verify_buf(key, "10.0.0.2", 8, sig, siglen,
                              "hello world!", 12);
    if(ret!=0)
        printf("2:verification result correct!\n");
    else
        printf("2:Failed!\n");
    ret=joseph_ibs_verify_buf(key, "10.0.0.1", 8, sig, siglen,
                             "hello1world!", 12);
    if(ret!=0) //
       printf("3:verification result correct!\n");
    else
       printf("3:Failed!\n");

*/
//proposed offline/online verifier test

    int ret=joseph_ibs_offline_verify(key,"verifybinx","verigybiny");

    ret=joseph_ibs_online_verify(key, "verifybinx","verigybiny","10.0.0.1", 8, sig, siglen,
                                  "hello world!", 12);

    if(ret==0)  // should be successful
       printf("improved 1:verification result correct!\n");
    else
       printf("improved 1:Failed!\n");

/*

    ret=joseph_ibs_online_verify(key, "verifybinx","verigybiny","10.0.0.2", 8, sig, siglen,
                                  "hello world!", 12);

    if(ret!=0)
       printf("improved 2:verification result correct!\n");
    else
       printf("improved 2:Failed!\n");



    ret=joseph_ibs_online_verify(key, "verifybinx","verigybiny","10.0.0.1", 8, sig, siglen,
                                  "hello1world!", 12);

    if(ret!=0)
       printf("improved 3:verification result correct!\n");
    else
       printf("improved 3:Failed!\n");

   // PROF_STDOUT();
//test of ternary expansion precompute

*/

    return 0;
}


