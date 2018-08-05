/*
*   A byte-oriented AES-256-CTR implementation.
*   Based on the code available at http://www.literatecode.com/aes256
*   Complies with RFC3686, http://tools.ietf.org/html/rfc3686
*
*/
#include "aes256.h"

/* #define BACK_TO_TABLES */

#ifndef BACK_TO_TABLES
static uint8_t gf_alog(uint8_t x);
static uint8_t gf_log(uint8_t x);
static uint8_t gf_mulinv(uint8_t x);
static uint8_t rj_sbox(uint8_t x);
#endif
static uint8_t rj_xtime(uint8_t x);
static void aes_subBytes(uint8_t *buf);
static void aes_addRoundKey(uint8_t *buf, uint8_t *key);
static void aes_addRoundKey_cpy(uint8_t *buf, uint8_t *key, uint8_t *cpk);
static void aes_shiftRows(uint8_t *buf);
static void aes_mixColumns(uint8_t *buf);
static void aes_expandEncKey(uint8_t *k, uint8_t rc);
static void ctr_inc_ctr(uint8_t *val);
static void ctr_clock_keystream(aes256_context *ctx, uint8_t *ks);

#ifdef BACK_TO_TABLES

static const uint8_t sbox[256] = {
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
	0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
	0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
	0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
	0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
	0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
	0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
	0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
	0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
	0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
	0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
	0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
	0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
	0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
	0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
	0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
	0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

#define rj_sbox(x)    sbox[(x)]

#else /* tableless subroutines */

/* -------------------------------------------------------------------------- */
static uint8_t gf_alog(uint8_t x) /* calculate anti-logarithm gen 3 */
{
	uint8_t y = 1, i;

	for (i = 0; i < x; i++)
		y ^= rj_xtime(y);

	return y;
} /* gf_alog */

/* -------------------------------------------------------------------------- */
static uint8_t gf_log(uint8_t x) /* calculate logarithm gen 3 */
{
	uint8_t y, i = 0;

	if ( x > 0 )
		for (i = y = 1; i > 0; i++ ) {
			y ^= rj_xtime(y);
			if (y == x)
				break;
		}

	return i;
} /* gf_log */

/* -------------------------------------------------------------------------- */
static uint8_t gf_mulinv(uint8_t x) /* calculate multiplicative inverse */
{
	return ( x > 0 ) ? gf_alog(255 - gf_log(x)) : 0;
} /* gf_mulinv */

/* -------------------------------------------------------------------------- */
static uint8_t rj_sbox(uint8_t x)
{
	uint8_t y, sb;

	sb = y = gf_mulinv(x);
	y  = (uint8_t)((y << 1) | (y >> 7)) & 0xFF;
	sb ^= y;
	y  = (uint8_t)((y << 1) | (y >> 7)) & 0xFF;
	sb ^= y;
	y  = (uint8_t)((y << 1) | (y >> 7)) & 0xFF;
	sb ^= y;
	y  = (uint8_t)((y << 1) | (y >> 7)) & 0xFF;
	sb ^= y;

	return (sb ^ 0x63);
} /* rj_sbox */

#endif

static uint8_t rj_xtime(uint8_t x)
{
	return ((x << 1) & 0xFF) ^ (0x1b * ((x & 0x80) >> 7) );
} /* rj_xtime */

/* -------------------------------------------------------------------------- */
static void aes_subBytes(uint8_t *buf)
{
	register uint8_t i;

	for (i = 0; i < 16; i++)
		buf[i] = rj_sbox(buf[i]);

} /* aes_subBytes */

/* -------------------------------------------------------------------------- */
static void aes_addRoundKey(uint8_t *buf, uint8_t *key)
{
	register uint8_t i;

	for (i = 0; i < 16; i++)
		buf[i] ^= key[i];

} /* aes_addRoundKey */

/* -------------------------------------------------------------------------- */
static void aes_addRoundKey_cpy(uint8_t *buf, uint8_t *key, uint8_t *cpk)
{
	register uint8_t i = 16;

	for (i = 0; i < 16; i++) {
		cpk[i]  = key[i];
		buf[i] ^= key[i];
		cpk[16 + i] = key[16 + i];
	}

} /* aes_addRoundKey_cpy */

/* -------------------------------------------------------------------------- */
static void aes_shiftRows(uint8_t *buf)
{
	register uint8_t i = buf[1], j = buf[3], k = buf[10], l = buf[14];

	buf[1]  = buf[5];
	buf[5]  = buf[9];
	buf[9]  = buf[13];
	buf[13] = i;
	buf[3]  = buf[15];
	buf[15] = buf[11];
	buf[11] = buf[7];
	buf[7]  = j;
	buf[10] = buf[2];
	buf[2]  = k;
	buf[14] = buf[6];
	buf[6]  = l;

} /* aes_shiftRows */

/* -------------------------------------------------------------------------- */
static void aes_mixColumns(uint8_t *buf)
{
	register uint8_t i, a, b, c, d, e;

	for (i = 0; i < 16; i += 4) {
		a = buf[i];
		b = buf[i + 1];
		c = buf[i + 2];
		d = buf[i + 3];
		e = a ^ b ^ c ^ d;
		buf[i]     ^= e ^ rj_xtime(a ^ b);
		buf[i + 1] ^= e ^ rj_xtime(b ^ c);
		buf[i + 2] ^= e ^ rj_xtime(c ^ d);
		buf[i + 3] ^= e ^ rj_xtime(d ^ a);
	}

} /* aes_mixColumns */

/* -------------------------------------------------------------------------- */
static void aes_expandEncKey(uint8_t *k, uint8_t rc)
{
	register uint8_t i;

	k[0] ^= rj_sbox(k[29]) ^ rc;
	k[1] ^= rj_sbox(k[30]);
	k[2] ^= rj_sbox(k[31]);
	k[3] ^= rj_sbox(k[28]);

	for(i = 4; i < 16; i += 4) {
		k[i]     ^= k[i - 4];
		k[i + 1] ^= k[i - 3];
		k[i + 2] ^= k[i - 2];
		k[i + 3] ^= k[i - 1];
	}
	k[16] ^= rj_sbox(k[12]);
	k[17] ^= rj_sbox(k[13]);
	k[18] ^= rj_sbox(k[14]);
	k[19] ^= rj_sbox(k[15]);

	for(i = 20; i < 32; i += 4) {
		k[i]     ^= k[i - 4];
		k[i + 1] ^= k[i - 3];
		k[i + 2] ^= k[i - 2];
		k[i + 3] ^= k[i - 1];
	}

} /* aes_expandEncKey */

/* -------------------------------------------------------------------------- */
void aes256_init(aes256_context *ctx, uint8_t *k)
{
	register uint8_t i;

	for (i = 0; i < sizeof(ctx->key); i++)
		ctx->enckey[i] = k[i];

} /* aes256_init */

/* -------------------------------------------------------------------------- */
void aes256_done(aes256_context *ctx)
{
	register uint8_t i;

	for (i = 0; i < sizeof(ctx->key); i++) {
		ctx->key[i] = ctx->enckey[i] = 0;
		ctx->blk.nonce[i % sizeof(ctx->blk.nonce)] = 0;
		ctx->blk.iv[i % sizeof(ctx->blk.iv)] = 0;
		ctx->blk.ctr[i % sizeof(ctx->blk.ctr)] = 0;
	}

} /* aes256_done */

/* -------------------------------------------------------------------------- */
void aes256_encrypt_ecb(aes256_context *ctx, uint8_t *buf)
{
	uint8_t i, rcon = 1;

	aes_addRoundKey_cpy(buf, ctx->enckey, ctx->key);
	for(i = 1; i < 14; ++i) {
		aes_subBytes(buf);
		aes_shiftRows(buf);
		aes_mixColumns(buf);
		if( (i & 1) == 1 )
			aes_addRoundKey(buf, &ctx->key[16]);
		else {
			aes_expandEncKey(ctx->key, rcon);
			rcon = rj_xtime(rcon);
			aes_addRoundKey(buf, ctx->key);
		}
	}
	aes_subBytes(buf);
	aes_shiftRows(buf);
	aes_expandEncKey(ctx->key, rcon);
	aes_addRoundKey(buf, ctx->key);

} /* aes256_encrypt */

/* -------------------------------------------------------------------------- */
static void ctr_inc_ctr(uint8_t *val)
{
	if ( val != NULL )
		if ( ++val[3] == 0 )
			if ( ++val[2] == 0 )
				if ( ++val[1] == 0 )
					val[0]++;

} /* ctr_inc_ctr */

/* -------------------------------------------------------------------------- */
static void ctr_clock_keystream(aes256_context *ctx, uint8_t *ks)
{
	uint8_t i;
	uint8_t *p = (uint8_t *)&ctx->blk;

	if ( (ctx != NULL) && (ks != NULL) ) {
		for (i = 0; i < sizeof(ctx->blk); i++)
			ks[i] = p[i];

		aes256_encrypt_ecb(ctx, ks);
		ctr_inc_ctr(&ctx->blk.ctr[0]);
	}

} /* ctr_clock_keystream */

/* -------------------------------------------------------------------------- */
void aes256_setCtrBlk(aes256_context *ctx, rfc3686_blk *blk)
{
	uint8_t i, *p = (uint8_t *)&ctx->blk, *v = (uint8_t *)blk;

	if ( (ctx != NULL) && (blk != NULL) )
		for (i = 0; i < sizeof(ctx->blk); i++)
			p[i] = v[i];

} /* aes256_setCtrBlk */

/* -------------------------------------------------------------------------- */
void aes256_encrypt_ctr(aes256_context *ctx, uint8_t *buf, size_t sz)
{
	uint8_t key[sizeof(ctx->blk)];
	size_t  i;
	uint8_t j = sizeof(key);

	for (i = 0; i < sz; i++) {
		if ( j == sizeof(key) ) {
			j = 0;
			ctr_clock_keystream(ctx, key);
		}
		buf[i] ^= key[j++];
	}

} /* aes256_encrypt_ctr */
