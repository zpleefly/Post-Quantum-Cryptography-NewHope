/*
 *   Project: Implementation of NewHope
 */

#include "new_hope.h"
#include "ntt_constants.h"
#include "secure_random.h"
#include <string.h>

#define ABS(value)  (((value) < 0) ? (value)*-1 : (value))
#define SET_BIT(value, bit)        ((value) | ((u8)1 << (bit)))
#define GET_BIT(value, bit)       ((((value) >> (bit)) & (u8)1))

/**********************************************************************/
/*                       Helper Functions                             */
/**********************************************************************/

/*
 * Computes the hamming weight of a byte, i.e. the number of 1 bits.
 *
 * @param[in] value - the value to compute the HW of
 * @returns The hamming weight.
 */
u8 hw(u8 value)
{
    u8 cnt = 0;
    while (value > 0)
    {
        cnt += value & 1;
        value >>= 1;
    }

    return cnt;
}

/*
 * Generates polynomial "a" of the new hope key exchange.
 * All coefficients are random values mod q.
 *
 * @param[out] poly - the output polynomial
 */
void generate_a(new_hope_poly* poly)
{
    for (u32 i = 0; i < NEWHOPE_N; ++i)
    {
        poly->coefficients[i] = secure_rand() % NEWHOPE_Q;
    }
}

/*
 * Samples a random polynomial from a binomial distribution.
 *
 * @param[out] poly - the output polynomial
 */
void sample_random_poly(new_hope_poly* poly)
{
    for (u32 i = 0; i < NEWHOPE_N; ++i)
    {
        poly->coefficients[i] = (NEWHOPE_Q + hw(secure_rand()) - hw(secure_rand())) % NEWHOPE_Q;
    }
}

/*
 * Copies a polynomial.
 *
 * @param[out] dest - the destination polynomial
 * @param[in] src - the source polynomial
 */
void copy_poly(new_hope_poly* dest, const new_hope_poly* src)
{
    for (u32 i = 0; i < NEWHOPE_N; ++i)
    {
        dest->coefficients[i] = src->coefficients[i];
    }
}


/**********************************************************************/
/*                       Message Encoding                             */
/**********************************************************************/

/*
 * Encodes a message into a polynomial.
 *
 * @param[out] poly - the output polynomial
 * @param[in] message - the 32 byte message to encode
 */
void encode_message(new_hope_poly* poly, const u8 message[])
{
    u16 shifted_q = NEWHOPE_Q >> 1;
    for(int byteIndex = 0; byteIndex < 32; byteIndex++)
    {
        u8 byte = message[byteIndex];
        for(int bitIndex = 0; bitIndex < 8; bitIndex++)
        {
            u16 encoding;
            if(GET_BIT(byte, bitIndex))
                encoding = shifted_q;
            else
                encoding = 0;

            poly->coefficients[byteIndex*8 + bitIndex] = encoding;
            poly->coefficients[byteIndex*8 + bitIndex + 256] = encoding;
            poly->coefficients[byteIndex*8 + bitIndex + 512] = encoding;
            poly->coefficients[byteIndex*8 + bitIndex + 768] = encoding;
        }
    }
}

/*
 * Decodes a polynomial into a binary message.
 *
 * @param[out] message - the 32 byte message encoded by the polynomial
 * @param[in] poly - the polynomial
 */
void decode_message(u8 message[], const new_hope_poly* poly)
{


    u16 shifted_q = NEWHOPE_Q >> 1;
    for(u8 byteIndex = 0; byteIndex < 32; byteIndex++)
    {
        u8 byte = 0;
        for(u8 bitIndex = 0; bitIndex < 8; bitIndex++)
        {
            u16 t = (u16)ABS((i32)(poly->coefficients[byteIndex*8 + bitIndex] - shifted_q));
            t += (u16)ABS((i32)(poly->coefficients[byteIndex*8 + bitIndex + 256] - shifted_q));
            t += (u16)ABS((i32)(poly->coefficients[byteIndex*8 + bitIndex + 512] - shifted_q));
            t += (u16)ABS((i32)(poly->coefficients[byteIndex*8 + bitIndex + 768] - shifted_q));

            if(t <= NEWHOPE_Q)
                byte = SET_BIT(byte, bitIndex);
        }
        message[byteIndex] = byte;
    }
}


/**********************************************************************/
/*                   Polynomial Arithmetic                            */
/**********************************************************************/

/*
 * Add two polynomials component wise.
 * Computes res = a + b.
 *
 * @param[out] res - the output polynomial
 * @param[in] a - the first polynomial
 * @param[in] b - the second polynomial
 */
void poly_add(new_hope_poly* res, const new_hope_poly* a, const new_hope_poly* b)
{
    //component-wise addition
    for(u16 i=0; i < NEWHOPE_N; i++)
        res->coefficients[i] = (a->coefficients[i] + b->coefficients[i]) % (u16)NEWHOPE_Q;
}

/*
 * Subtracts two polynomials component wise.
 * Computes res = a - b.
 *
 * @param[out] res - the output polynomial
 * @param[in] a - the first polynomial
 * @param[in] b - the second polynomial
 */
void poly_sub(new_hope_poly* res, const new_hope_poly* a, const new_hope_poly* b)
{
    for(u16 i=0; i < NEWHOPE_N; i++)
    {
        //result could be negative here
        i32 tmp = (a->coefficients[i] - b->coefficients[i]) % (u16)NEWHOPE_Q;

        if(tmp < 0) // we want to have the positive reduced result.
            tmp += NEWHOPE_Q;

        res->coefficients[i] = (u16)tmp;
    }
}

/*
 * Multiplies two polynomials using schoolbook multiplication.
 * Computes res = a * b.
 *
 * @param[out] res - the output polynomial
 * @param[in] a - the first polynomial
 * @param[in] b - the second polynomial
 */
void poly_mul(new_hope_poly* res, const new_hope_poly* a, const new_hope_poly* b)
{
    new_hope_poly a_cp, b_cp; // make sure to not overwrite the operands (if also passed as res ptr)
    copy_poly(&a_cp, a);
    copy_poly(&b_cp, b);

    for(u16 i=0; i<NEWHOPE_N; i++) // make sure to have an empty result buffer
        res->coefficients[i] = 0;

    for(u16 i=0; i < NEWHOPE_N; i++)
    {
        u16 coeff = a_cp.coefficients[i];
        for(u16 j=0; j < NEWHOPE_N; j++)
        {
            i32 tmp = (coeff * b_cp.coefficients[j]) % NEWHOPE_Q;
            i16 exp = (i16)((i+j)/NEWHOPE_N); //casting to int means, to take only the integral part before the decimal point, so basically rounding off
            if( exp % 2 != 0) //if uneven, then negate
            {
                tmp *= -1;
                tmp += NEWHOPE_Q; //get positive result
            }

            u16 resIndex = (i+j) % (u16)NEWHOPE_N;
            res->coefficients[resIndex] += tmp;
            res->coefficients[resIndex] %= (u16)NEWHOPE_Q;
        }
    }
}


/**********************************************************************/
/*            New Hope with schoolbook arithmetic                     */
/**********************************************************************/

/*
 * Executes the NewHope key generation.
 *
 * @param[out] pk - the public key
 * @param[out] sk - the secret key
 */
void new_hope_keygen(new_hope_pk* pk, new_hope_sk* sk)
{
    new_hope_poly a, s, e, b;
    generate_a(&a);
    sample_random_poly(&s);
    sample_random_poly(&e);

    poly_mul(&b,&a,&s); // a*s
    poly_add(&b,&b,&e); // +e

    //return result
    pk->a = a;
    pk->b = b;
    sk->s = s;
}

/*
 * Executes a NewHope encryption of a 32 byte message.
 *
 * @param[in] pk - the public key
 * @param[in] message - the 32 byte message
 * @param[out] ct - the ciphertext
 */
void new_hope_encrypt(const new_hope_pk* pk, const u8 message[], new_hope_ciphertext* ct)
{
    new_hope_poly s, e1, e2, u, m, v;
    sample_random_poly(&s);
    sample_random_poly(&e1);
    sample_random_poly(&e2);

    poly_mul(&u, &pk->a, &s); //  a*s'
    poly_add(&u, &u, &e1); // + e'

    //encode message to get the poly format
    encode_message(&m, message);

    poly_mul(&v,&pk->b,&s); // b * s'
    poly_add(&v,&v,&e2); // + e''
    poly_add(&v,&v,&m); // + m

    //return result
    ct->u = u;
    ct->v = v;
}

/*
 * Executes a NewHope decryption of a ciphertext to a 32 byte message.
 *
 * @param[in] sk - the secret key
 * @param[in] ct - the ciphertext
 * @param[out] message - the 32 byte plaintext
 */
void new_hope_decrypt(const new_hope_sk* sk, const new_hope_ciphertext* ct, u8 message[])
{
    new_hope_poly t,us;
    poly_mul(&us,&ct->u, &sk->s); // u*s
    poly_sub(&t, &ct->v, &us); // t = v - u*s

    //decode and return plaintext
    decode_message(message, &t);
}


/**********************************************************************/
/*                             NTT                                    */
/**********************************************************************/

/*
 * Transforms a polynomial into NTT domain.
 * This operation is done in-place, i.e. the input parameter is changed.
 *
 * @param[inout] poly - the polynomial to transform
 */
void ntt(new_hope_poly* poly)
{
    u16 m = 1;
    u16 k = NEWHOPE_N >> 1;
    while(m < NEWHOPE_N)
    {
        for(u16 i=0; i < m; i++)
        {
            u16 jFirst = (u16)2 * i * k;
            u16 jLast = jFirst + k - (u16)1;

            for(u16 j=jFirst; j<= jLast; j++)
            {
                u16 l = j + k;
                i32 t = (poly->coefficients[j]);
                i32 u = (poly->coefficients[l] * ntt_psi[m+i]) ;
                poly->coefficients[j] = (u16)((t + u) % NEWHOPE_Q);

                i32 tmp = (t - u) % NEWHOPE_Q; // we have to make sure that we always get the positive reduced result
                if(tmp < 0)
                    tmp += NEWHOPE_Q; //get positive result

                poly->coefficients[l] = (u16)tmp;
            }
        }
        m <<= 1;
        k >>= 1;
    }
}

/*
 * Transforms a polynomial back to normal domain.
 * This operation is done in-place, i.e. the input parameter is changed.
 *
 * @param[inout] poly - the polynomial to transform
 */
void inv_ntt(new_hope_poly* poly)
{
    u16 k = 1;
    u16 m = NEWHOPE_N >> 1;

    while(m >= 1)
    {
        for(u16 i=0; i < m; i++)
        {
            u16 jFirst = (u16)2 * i * k;
            u16 jLast = jFirst + k - (u16)1;

            for(u16 j=jFirst; j<= jLast; j++)
            {
                u16 l = j + k;
                i32 t = poly->coefficients[j];
                i32 u = poly->coefficients[l];
                poly->coefficients[j] = (u16)((t + u) % NEWHOPE_Q);

                i32 tmp = (t - u) % NEWHOPE_Q; // we have to make sure that we always get the positive reduced result
                if(tmp < 0)
                    tmp += NEWHOPE_Q; //get positive result

                poly->coefficients[l] = (u16)((tmp * ntt_inv_psi[m+i]) % NEWHOPE_Q); //reduce before casting to u16
            }
        }
        m >>= 1;
        k <<= 1;
    }

    //scale with n^-1
    for(int i=0; i <NEWHOPE_N;i++)
        poly->coefficients[i] = (u16)((poly->coefficients[i] * NEWHOPE_INV_N) % NEWHOPE_Q); //reduce before casting to u16
}

/*
 * Multiplies two polynomials in NTT domain.
 *
 * @param[out] res - the output polynomial in NTT domain
 * @param[in] a - the first polynomial in NTT domain
 * @param[in] b - the second polynomial in NTT domain
 */
void ntt_mul(new_hope_poly* res, const new_hope_poly* a, const new_hope_poly* b)
{
    //in NTT domain: component-wise multiplication
    for(int i=0; i < NEWHOPE_N; i++)
        res->coefficients[i] = (a->coefficients[i] * b->coefficients[i]) % (u16)NEWHOPE_Q;
}


/**********************************************************************/
/*                        New Hope with NTT                           */
/**********************************************************************/

/*
 * Executes the NewHope key generation.
 *
 * @param[out] pk - the public key
 * @param[out] sk - the secret key
 */
void new_hope_keygen_ntt(new_hope_pk* pk, new_hope_sk* sk)
{
    new_hope_poly a, s, e, b;
    generate_a(&a);

    sample_random_poly(&s);
    ntt(&s);

    sample_random_poly(&e);
    ntt(&e);

    ntt_mul(&b, &a, &s); // a ° s
    poly_add(&b, &b, &e);

    //return result
    pk->a = a;
    pk->b = b;
    sk->s = s;
}

/*
 * Executes a NewHope encryption of a 32 byte message.
 *
 * @param[in] pk - the public key
 * @param[in] message - the 32 byte message
 * @param[out] ct - the ciphertext
 */
void new_hope_encrypt_ntt(const new_hope_pk* pk, const u8 message[], new_hope_ciphertext* ct)
{
    new_hope_poly s, e1, e2, u, bs, m, v;

    sample_random_poly(&s);
    ntt(&s);
    sample_random_poly(&e1);
    ntt(&e1);

    //e2 is not in ntt domain
    sample_random_poly(&e2);

    ntt_mul(&u, &pk->a, &s); // a ° s'
    poly_add(&u, &u, &e1); // + e'

    ntt_mul(&bs, &pk->b, &s); // b ° s
    inv_ntt(&bs); // InvNTT(b ° s)

    encode_message(&m,message);

    poly_add(&v, &bs, &e2); // InvNTT(b ° s) + e''
    poly_add(&v, &v, &m); // + m

    //return result
    ct->v = v;
    ct->u = u;
}

/*
 * Executes a NewHope decryption of a ciphertext to a 32 byte message.
 *
 * @param[in] sk - the secret key
 * @param[in] ct - the ciphertext
 * @param[out] message - the 32 byte plaintext
 */
void new_hope_decrypt_ntt(const new_hope_sk* sk, const new_hope_ciphertext* ct, u8 message[])
{
    new_hope_poly t, us;

    ntt_mul(&us, &ct->u, &sk->s); // u ° s
    inv_ntt(&us); // InvNTT(u ° s)

    poly_sub(&t, &ct->v, &us); // t = v - InvNTT(u ° s)

    //result
    decode_message(message, &t);
}

