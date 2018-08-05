#ifndef __NEW_HOPE_H__
#define __NEW_HOPE_H__

#include "types.h"

#define NEWHOPE_N 1024
#define NEWHOPE_INV_N 12277
#define NEWHOPE_Q 12289

typedef struct
{
    u16 coefficients[NEWHOPE_N];
} new_hope_poly;

typedef struct
{
    new_hope_poly a;
    new_hope_poly b;
} new_hope_pk;

typedef struct
{
    new_hope_poly s;
} new_hope_sk;

typedef struct
{
    new_hope_poly u;
    new_hope_poly v;
} new_hope_ciphertext;


void copy_poly(new_hope_poly* dest, const new_hope_poly* src);

void encode_message(new_hope_poly* poly, const u8 message[]);
void decode_message(u8 message[], const new_hope_poly* poly);

void poly_add(new_hope_poly* res, const new_hope_poly* a, const new_hope_poly* b);
void poly_sub(new_hope_poly* res, const new_hope_poly* a, const new_hope_poly* b);
void poly_mul(new_hope_poly* res, const new_hope_poly* a, const new_hope_poly* b);

void new_hope_keygen(new_hope_pk* pk, new_hope_sk* sk);
void new_hope_encrypt(const new_hope_pk* pk, const u8 message[32], new_hope_ciphertext* ct);
void new_hope_decrypt(const new_hope_sk* sk, const new_hope_ciphertext* ct, u8 message[32]);

void ntt(new_hope_poly* poly);
void inv_ntt(new_hope_poly* poly);
void ntt_mul(new_hope_poly* res, const new_hope_poly* a, const new_hope_poly* b);

void new_hope_keygen_ntt(new_hope_pk* pk, new_hope_sk* sk);
void new_hope_encrypt_ntt(const new_hope_pk* pk, const u8 message[32], new_hope_ciphertext* ct);
void new_hope_decrypt_ntt(const new_hope_sk* sk, const new_hope_ciphertext* ct, u8 message[32]);


#endif
