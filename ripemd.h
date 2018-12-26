/*
 * Cryptographic API.
 *
 * RIPEMD-160 - RACE Integrity Primitives Evaluation Message Digest.
 *
 * Based on the reference implementation by Antoon Bosselaers, ESAT-COSIC
 *
 * Copyright (c) 2008 Adrian-Ken Rueegsegger <ken@codelabs.ch>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 */

#include "externs.h"
#define SHA256_DIGEST_LENGTH 32
#define RIPEMD160_DIGEST_LENGTH 20


typedef struct {
	unsigned int s[32];
	unsigned int buf[16]; /* In big endian */
	size_t bytes;
} sha256_t;

#define Ch(x,y,z) ((z) ^ ((x) & ((y) ^ (z))))
#define Maj(x,y,z) (((x) & (y)) | ((z) & ((x) | (y))))
#define Sigma0(x) (((x) >> 2 | (x) << 30) ^ ((x) >> 13 | (x) << 19) ^ ((x) >> 22 | (x) << 10))
#define Sigma1(x) (((x) >> 6 | (x) << 26) ^ ((x) >> 11 | (x) << 21) ^ ((x) >> 25 | (x) << 7))
#define sigma0(x) (((x) >> 7 | (x) << 25) ^ ((x) >> 18 | (x) << 14) ^ ((x) >> 3))
#define sigma1(x) (((x) >> 17 | (x) << 15) ^ ((x) >> 19 | (x) << 13) ^ ((x) >> 10))
#define Round(a,b,c,d,e,f,g,h,k,w) do { \
    unsigned int t1 = (h) + Sigma1(e) + Ch((e), (f), (g)) + (k) + (w); \
    unsigned int t2 = Sigma0(a) + Maj((a), (b), (c)); \
    (d) += t1; \
    (h) = t1 + t2; \
} while(0)
#define BE32(p) ((((p) & 0xFF) << 24) | (((p) & 0xFF00) << 8) | (((p) & 0xFF0000) >> 8) | (((p) & 0xFF000000) >> 24))

void sha256_initialize(sha256_t *hash) {
	hash->s[0] = 0x6a09e667ul;
	hash->s[1] = 0xbb67ae85ul;
	hash->s[2] = 0x3c6ef372ul;
	hash->s[3] = 0xa54ff53aul;
	hash->s[4] = 0x510e527ful;
	hash->s[5] = 0x9b05688cul;
	hash->s[6] = 0x1f83d9abul;
	hash->s[7] = 0x5be0cd19ul;
	hash->bytes = 0;
}
void sha256_transform(unsigned int* s, const unsigned int* chunk) {
	unsigned int a = s[0], b = s[1], c = s[2], d = s[3], e = s[4], f = s[5], g = s[6], h = s[7];
	unsigned int w0, w1, w2, w3, w4, w5, w6, w7, w8, w9, w10, w11, w12, w13, w14, w15;

	Round(a, b, c, d, e, f, g, h, 0x428a2f98, w0 = BE32(chunk[0]));
	Round(h, a, b, c, d, e, f, g, 0x71374491, w1 = BE32(chunk[1]));
	Round(g, h, a, b, c, d, e, f, 0xb5c0fbcf, w2 = BE32(chunk[2]));
	Round(f, g, h, a, b, c, d, e, 0xe9b5dba5, w3 = BE32(chunk[3]));
	Round(e, f, g, h, a, b, c, d, 0x3956c25b, w4 = BE32(chunk[4]));
	Round(d, e, f, g, h, a, b, c, 0x59f111f1, w5 = BE32(chunk[5]));
	Round(c, d, e, f, g, h, a, b, 0x923f82a4, w6 = BE32(chunk[6]));
	Round(b, c, d, e, f, g, h, a, 0xab1c5ed5, w7 = BE32(chunk[7]));
	Round(a, b, c, d, e, f, g, h, 0xd807aa98, w8 = BE32(chunk[8]));
	Round(h, a, b, c, d, e, f, g, 0x12835b01, w9 = BE32(chunk[9]));
	Round(g, h, a, b, c, d, e, f, 0x243185be, w10 = BE32(chunk[10]));
	Round(f, g, h, a, b, c, d, e, 0x550c7dc3, w11 = BE32(chunk[11]));
	Round(e, f, g, h, a, b, c, d, 0x72be5d74, w12 = BE32(chunk[12]));
	Round(d, e, f, g, h, a, b, c, 0x80deb1fe, w13 = BE32(chunk[13]));
	Round(c, d, e, f, g, h, a, b, 0x9bdc06a7, w14 = BE32(chunk[14]));
	Round(b, c, d, e, f, g, h, a, 0xc19bf174, w15 = BE32(chunk[15]));

	Round(a, b, c, d, e, f, g, h, 0xe49b69c1, w0 += sigma1(w14) + w9 + sigma0(w1));
	Round(h, a, b, c, d, e, f, g, 0xefbe4786, w1 += sigma1(w15) + w10 + sigma0(w2));
	Round(g, h, a, b, c, d, e, f, 0x0fc19dc6, w2 += sigma1(w0) + w11 + sigma0(w3));
	Round(f, g, h, a, b, c, d, e, 0x240ca1cc, w3 += sigma1(w1) + w12 + sigma0(w4));
	Round(e, f, g, h, a, b, c, d, 0x2de92c6f, w4 += sigma1(w2) + w13 + sigma0(w5));
	Round(d, e, f, g, h, a, b, c, 0x4a7484aa, w5 += sigma1(w3) + w14 + sigma0(w6));
	Round(c, d, e, f, g, h, a, b, 0x5cb0a9dc, w6 += sigma1(w4) + w15 + sigma0(w7));
	Round(b, c, d, e, f, g, h, a, 0x76f988da, w7 += sigma1(w5) + w0 + sigma0(w8));
	Round(a, b, c, d, e, f, g, h, 0x983e5152, w8 += sigma1(w6) + w1 + sigma0(w9));
	Round(h, a, b, c, d, e, f, g, 0xa831c66d, w9 += sigma1(w7) + w2 + sigma0(w10));
	Round(g, h, a, b, c, d, e, f, 0xb00327c8, w10 += sigma1(w8) + w3 + sigma0(w11));
	Round(f, g, h, a, b, c, d, e, 0xbf597fc7, w11 += sigma1(w9) + w4 + sigma0(w12));
	Round(e, f, g, h, a, b, c, d, 0xc6e00bf3, w12 += sigma1(w10) + w5 + sigma0(w13));
	Round(d, e, f, g, h, a, b, c, 0xd5a79147, w13 += sigma1(w11) + w6 + sigma0(w14));
	Round(c, d, e, f, g, h, a, b, 0x06ca6351, w14 += sigma1(w12) + w7 + sigma0(w15));
	Round(b, c, d, e, f, g, h, a, 0x14292967, w15 += sigma1(w13) + w8 + sigma0(w0));

	Round(a, b, c, d, e, f, g, h, 0x27b70a85, w0 += sigma1(w14) + w9 + sigma0(w1));
	Round(h, a, b, c, d, e, f, g, 0x2e1b2138, w1 += sigma1(w15) + w10 + sigma0(w2));
	Round(g, h, a, b, c, d, e, f, 0x4d2c6dfc, w2 += sigma1(w0) + w11 + sigma0(w3));
	Round(f, g, h, a, b, c, d, e, 0x53380d13, w3 += sigma1(w1) + w12 + sigma0(w4));
	Round(e, f, g, h, a, b, c, d, 0x650a7354, w4 += sigma1(w2) + w13 + sigma0(w5));
	Round(d, e, f, g, h, a, b, c, 0x766a0abb, w5 += sigma1(w3) + w14 + sigma0(w6));
	Round(c, d, e, f, g, h, a, b, 0x81c2c92e, w6 += sigma1(w4) + w15 + sigma0(w7));
	Round(b, c, d, e, f, g, h, a, 0x92722c85, w7 += sigma1(w5) + w0 + sigma0(w8));
	Round(a, b, c, d, e, f, g, h, 0xa2bfe8a1, w8 += sigma1(w6) + w1 + sigma0(w9));
	Round(h, a, b, c, d, e, f, g, 0xa81a664b, w9 += sigma1(w7) + w2 + sigma0(w10));
	Round(g, h, a, b, c, d, e, f, 0xc24b8b70, w10 += sigma1(w8) + w3 + sigma0(w11));
	Round(f, g, h, a, b, c, d, e, 0xc76c51a3, w11 += sigma1(w9) + w4 + sigma0(w12));
	Round(e, f, g, h, a, b, c, d, 0xd192e819, w12 += sigma1(w10) + w5 + sigma0(w13));
	Round(d, e, f, g, h, a, b, c, 0xd6990624, w13 += sigma1(w11) + w6 + sigma0(w14));
	Round(c, d, e, f, g, h, a, b, 0xf40e3585, w14 += sigma1(w12) + w7 + sigma0(w15));
	Round(b, c, d, e, f, g, h, a, 0x106aa070, w15 += sigma1(w13) + w8 + sigma0(w0));

	Round(a, b, c, d, e, f, g, h, 0x19a4c116, w0 += sigma1(w14) + w9 + sigma0(w1));
	Round(h, a, b, c, d, e, f, g, 0x1e376c08, w1 += sigma1(w15) + w10 + sigma0(w2));
	Round(g, h, a, b, c, d, e, f, 0x2748774c, w2 += sigma1(w0) + w11 + sigma0(w3));
	Round(f, g, h, a, b, c, d, e, 0x34b0bcb5, w3 += sigma1(w1) + w12 + sigma0(w4));
	Round(e, f, g, h, a, b, c, d, 0x391c0cb3, w4 += sigma1(w2) + w13 + sigma0(w5));
	Round(d, e, f, g, h, a, b, c, 0x4ed8aa4a, w5 += sigma1(w3) + w14 + sigma0(w6));
	Round(c, d, e, f, g, h, a, b, 0x5b9cca4f, w6 += sigma1(w4) + w15 + sigma0(w7));
	Round(b, c, d, e, f, g, h, a, 0x682e6ff3, w7 += sigma1(w5) + w0 + sigma0(w8));
	Round(a, b, c, d, e, f, g, h, 0x748f82ee, w8 += sigma1(w6) + w1 + sigma0(w9));
	Round(h, a, b, c, d, e, f, g, 0x78a5636f, w9 += sigma1(w7) + w2 + sigma0(w10));
	Round(g, h, a, b, c, d, e, f, 0x84c87814, w10 += sigma1(w8) + w3 + sigma0(w11));
	Round(f, g, h, a, b, c, d, e, 0x8cc70208, w11 += sigma1(w9) + w4 + sigma0(w12));
	Round(e, f, g, h, a, b, c, d, 0x90befffa, w12 += sigma1(w10) + w5 + sigma0(w13));
	Round(d, e, f, g, h, a, b, c, 0xa4506ceb, w13 += sigma1(w11) + w6 + sigma0(w14));
	Round(c, d, e, f, g, h, a, b, 0xbef9a3f7, w14 + sigma1(w12) + w7 + sigma0(w15));
	Round(b, c, d, e, f, g, h, a, 0xc67178f2, w15 + sigma1(w13) + w8 + sigma0(w0));

	s[0] += a;
	s[1] += b;
	s[2] += c;
	s[3] += d;
	s[4] += e;
	s[5] += f;
	s[6] += g;
	s[7] += h;
}

void sha256_write(sha256_t *hash, const unsigned char *data, size_t len) {
	size_t bufsize = hash->bytes & 0x3F;
	hash->bytes += len;
	while (bufsize + len >= 64) {
		/* Fill the buffer, and process it. */
		memcpy(((unsigned char*)hash->buf) + bufsize, data, 64 - bufsize);
		data += 64 - bufsize;
		len -= 64 - bufsize;
		sha256_transform(hash->s, hash->buf);
		bufsize = 0;
	}
	if (len) {
		/* Fill the buffer with what remains. */
		memcpy(((unsigned char*)hash->buf) + bufsize, data, len);
	}
}

void sha256_finalize(sha256_t *hash, unsigned char *out32) {
	const unsigned char pad[64] = { 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
	unsigned int sizedesc[2];
	unsigned int out[8];
	int i = 0;
	sizedesc[0] = BE32(hash->bytes >> 29);
	sizedesc[1] = BE32(hash->bytes << 3);
	sha256_write(hash, pad, 1 + ((119 - (hash->bytes % 64)) % 64));
	sha256_write(hash, (const unsigned char*)sizedesc, 8);
	for (i = 0; i < 8; i++) {
		out[i] = BE32(hash->s[i]);
		hash->s[i] = 0;
	}
	memcpy(out32, (const unsigned char*)out, 32);
}

#undef Round
#undef sigma0
#undef sigma1
#undef Sigma0
#undef Sigma1
#undef Ch
#undef Maj
#undef ReadBE32
#undef WriteBE32


#define BYTES_TO_DWORD(strptr) (((unsigned int) *((strptr)+3) << 24) | ((unsigned int) *((strptr)+2) << 16) | ((unsigned int) *((strptr)+1) <<  8) | ((unsigned int) *(strptr)))
#define ROL(x, n)        (((x) << (n)) | ((x) >> (32-(n))))
#define F(x, y, z)        ((x) ^ (y) ^ (z)) 
#define FF(a, b, c, d, e, x, s) {(a) += ((b) ^ (c) ^ (d)) + (x);                          (a) = ROL((a), (s)) + (e);(c) = ROL((c), 10);}
#define GG(a, b, c, d, e, x, s) {(a) += (((b) & (c)) | (~(b) & (d))) + (x) + 0x5a827999UL;(a) = ROL((a), (s)) + (e);(c) = ROL((c), 10);}
#define HH(a, b, c, d, e, x, s) {(a) += (((b) | ~(c)) ^ (d)) + (x) + 0x6ed9eba1UL;        (a) = ROL((a), (s)) + (e);(c) = ROL((c), 10);}
#define II(a, b, c, d, e, x, s) {(a) += (((b) & (d)) | ((c) & ~(d))) + (x) + 0x8f1bbcdcUL;(a) = ROL((a), (s)) + (e);(c) = ROL((c), 10);}
#define JJ(a, b, c, d, e, x, s) {(a) += ((b) ^ ((c) | ~(d))) + (x) + 0xa953fd4eUL;        (a) = ROL((a), (s)) + (e);(c) = ROL((c), 10);}
#define FFF(a, b, c, d, e, x, s){(a) += ((b) ^ (c) ^ (d)) + (x);                          (a) = ROL((a), (s)) + (e);(c) = ROL((c), 10);}
#define GGG(a, b, c, d, e, x, s){(a) += (((b) & (c)) | (~(b) & (d))) + (x) + 0x7a6d76e9UL;(a) = ROL((a), (s)) + (e);(c) = ROL((c), 10);}
#define HHH(a, b, c, d, e, x, s){(a) += (((b) | ~(c)) ^ (d)) + (x) + 0x6d703ef3UL;        (a) = ROL((a), (s)) + (e);(c) = ROL((c), 10);}
#define III(a, b, c, d, e, x, s){(a) += (((b) & (d)) | ((c) & ~(d))) + (x) + 0x5c4dd124UL;(a) = ROL((a), (s)) + (e);(c) = ROL((c), 10);}
#define JJJ(a, b, c, d, e, x, s){(a) += ((b) ^ ((c) | ~(d))) + (x) + 0x50a28be6UL;        (a) = ROL((a), (s)) + (e);(c) = ROL((c), 10);}

void rmd160_transform(unsigned int *MDbuf, unsigned int *X)
{
	unsigned int aa = MDbuf[0], bb = MDbuf[1], cc = MDbuf[2], dd = MDbuf[3], ee = MDbuf[4];
	unsigned int aaa = MDbuf[0], bbb = MDbuf[1], ccc = MDbuf[2], ddd = MDbuf[3], eee = MDbuf[4];
	FF(aa, bb, cc, dd, ee, X[0], 11); FF(ee, aa, bb, cc, dd, X[1], 14); FF(dd, ee, aa, bb, cc, X[2], 15);
	FF(cc, dd, ee, aa, bb, X[3], 12); FF(bb, cc, dd, ee, aa, X[4], 5);  FF(aa, bb, cc, dd, ee, X[5], 8);
	FF(ee, aa, bb, cc, dd, X[6], 7);  FF(dd, ee, aa, bb, cc, X[7], 9);  FF(cc, dd, ee, aa, bb, X[8], 11);
	FF(bb, cc, dd, ee, aa, X[9], 13); FF(aa, bb, cc, dd, ee, X[10], 14); FF(ee, aa, bb, cc, dd, X[11], 15);
	FF(dd, ee, aa, bb, cc, X[12], 6); FF(cc, dd, ee, aa, bb, X[13], 7);	FF(bb, cc, dd, ee, aa, X[14], 9);
	FF(aa, bb, cc, dd, ee, X[15], 8);
	GG(ee, aa, bb, cc, dd, X[7], 7);  GG(dd, ee, aa, bb, cc, X[4], 6);  GG(cc, dd, ee, aa, bb, X[13], 8);
	GG(bb, cc, dd, ee, aa, X[1], 13); GG(aa, bb, cc, dd, ee, X[10], 11); GG(ee, aa, bb, cc, dd, X[6], 9);
	GG(dd, ee, aa, bb, cc, X[15], 7); GG(cc, dd, ee, aa, bb, X[3], 15);	GG(bb, cc, dd, ee, aa, X[12], 7);
	GG(aa, bb, cc, dd, ee, X[0], 12); GG(ee, aa, bb, cc, dd, X[9], 15);	GG(dd, ee, aa, bb, cc, X[5], 9);
	GG(cc, dd, ee, aa, bb, X[2], 11); GG(bb, cc, dd, ee, aa, X[14], 7);	GG(aa, bb, cc, dd, ee, X[11], 13);
	GG(ee, aa, bb, cc, dd, X[8], 12);
	HH(dd, ee, aa, bb, cc, X[3], 11); HH(cc, dd, ee, aa, bb, X[10], 13); HH(bb, cc, dd, ee, aa, X[14], 6);
	HH(aa, bb, cc, dd, ee, X[4], 7);  HH(ee, aa, bb, cc, dd, X[9], 14); HH(dd, ee, aa, bb, cc, X[15], 9);
	HH(cc, dd, ee, aa, bb, X[8], 13); HH(bb, cc, dd, ee, aa, X[1], 15);	HH(aa, bb, cc, dd, ee, X[2], 14);
	HH(ee, aa, bb, cc, dd, X[7], 8);  HH(dd, ee, aa, bb, cc, X[0], 13);	HH(cc, dd, ee, aa, bb, X[6], 6);
	HH(bb, cc, dd, ee, aa, X[13], 5); HH(aa, bb, cc, dd, ee, X[11], 12); HH(ee, aa, bb, cc, dd, X[5], 7);
	HH(dd, ee, aa, bb, cc, X[12], 5);
	II(cc, dd, ee, aa, bb, X[1], 11); II(bb, cc, dd, ee, aa, X[9], 12);	II(aa, bb, cc, dd, ee, X[11], 14);
	II(ee, aa, bb, cc, dd, X[10], 15); II(dd, ee, aa, bb, cc, X[0], 14);	II(cc, dd, ee, aa, bb, X[8], 15);
	II(bb, cc, dd, ee, aa, X[12], 9); II(aa, bb, cc, dd, ee, X[4], 8);	II(ee, aa, bb, cc, dd, X[13], 9);
	II(dd, ee, aa, bb, cc, X[3], 14); II(cc, dd, ee, aa, bb, X[7], 5);	II(bb, cc, dd, ee, aa, X[15], 6);
	II(aa, bb, cc, dd, ee, X[14], 8); II(ee, aa, bb, cc, dd, X[5], 6);	II(dd, ee, aa, bb, cc, X[6], 5);
	II(cc, dd, ee, aa, bb, X[2], 12);
	JJ(bb, cc, dd, ee, aa, X[4], 9);  JJ(aa, bb, cc, dd, ee, X[0], 15);	JJ(ee, aa, bb, cc, dd, X[5], 5);
	JJ(dd, ee, aa, bb, cc, X[9], 11); JJ(cc, dd, ee, aa, bb, X[7], 6);	JJ(bb, cc, dd, ee, aa, X[12], 8);
	JJ(aa, bb, cc, dd, ee, X[2], 13); JJ(ee, aa, bb, cc, dd, X[10], 12); JJ(dd, ee, aa, bb, cc, X[14], 5);
	JJ(cc, dd, ee, aa, bb, X[1], 12); JJ(bb, cc, dd, ee, aa, X[3], 13);	JJ(aa, bb, cc, dd, ee, X[8], 14);
	JJ(ee, aa, bb, cc, dd, X[11], 11); JJ(dd, ee, aa, bb, cc, X[6], 8);	JJ(cc, dd, ee, aa, bb, X[15], 5);
	JJ(bb, cc, dd, ee, aa, X[13], 6);
	JJJ(aaa, bbb, ccc, ddd, eee, X[5], 8); JJJ(eee, aaa, bbb, ccc, ddd, X[14], 9); JJJ(ddd, eee, aaa, bbb, ccc, X[7], 9);
	JJJ(ccc, ddd, eee, aaa, bbb, X[0], 11); JJJ(bbb, ccc, ddd, eee, aaa, X[9], 13); JJJ(aaa, bbb, ccc, ddd, eee, X[2], 15);
	JJJ(eee, aaa, bbb, ccc, ddd, X[11], 15); JJJ(ddd, eee, aaa, bbb, ccc, X[4], 5); JJJ(ccc, ddd, eee, aaa, bbb, X[13], 7);
	JJJ(bbb, ccc, ddd, eee, aaa, X[6], 7); JJJ(aaa, bbb, ccc, ddd, eee, X[15], 8); JJJ(eee, aaa, bbb, ccc, ddd, X[8], 11);
	JJJ(ddd, eee, aaa, bbb, ccc, X[1], 14); JJJ(ccc, ddd, eee, aaa, bbb, X[10], 14); JJJ(bbb, ccc, ddd, eee, aaa, X[3], 12);
	JJJ(aaa, bbb, ccc, ddd, eee, X[12], 6);
	III(eee, aaa, bbb, ccc, ddd, X[6], 9); III(ddd, eee, aaa, bbb, ccc, X[11], 13); III(ccc, ddd, eee, aaa, bbb, X[3], 15);
	III(bbb, ccc, ddd, eee, aaa, X[7], 7); III(aaa, bbb, ccc, ddd, eee, X[0], 12); III(eee, aaa, bbb, ccc, ddd, X[13], 8);
	III(ddd, eee, aaa, bbb, ccc, X[5], 9); III(ccc, ddd, eee, aaa, bbb, X[10], 11); III(bbb, ccc, ddd, eee, aaa, X[14], 7);
	III(aaa, bbb, ccc, ddd, eee, X[15], 7); III(eee, aaa, bbb, ccc, ddd, X[8], 12); III(ddd, eee, aaa, bbb, ccc, X[12], 7);
	III(ccc, ddd, eee, aaa, bbb, X[4], 6); III(bbb, ccc, ddd, eee, aaa, X[9], 15); III(aaa, bbb, ccc, ddd, eee, X[1], 13);
	III(eee, aaa, bbb, ccc, ddd, X[2], 11);
	HHH(ddd, eee, aaa, bbb, ccc, X[15], 9); HHH(ccc, ddd, eee, aaa, bbb, X[5], 7); HHH(bbb, ccc, ddd, eee, aaa, X[1], 15);
	HHH(aaa, bbb, ccc, ddd, eee, X[3], 11); HHH(eee, aaa, bbb, ccc, ddd, X[7], 8); HHH(ddd, eee, aaa, bbb, ccc, X[14], 6);
	HHH(ccc, ddd, eee, aaa, bbb, X[6], 6); HHH(bbb, ccc, ddd, eee, aaa, X[9], 14); HHH(aaa, bbb, ccc, ddd, eee, X[11], 12);
	HHH(eee, aaa, bbb, ccc, ddd, X[8], 13); HHH(ddd, eee, aaa, bbb, ccc, X[12], 5); HHH(ccc, ddd, eee, aaa, bbb, X[2], 14);
	HHH(bbb, ccc, ddd, eee, aaa, X[10], 13); HHH(aaa, bbb, ccc, ddd, eee, X[0], 13); HHH(eee, aaa, bbb, ccc, ddd, X[4], 7);
	HHH(ddd, eee, aaa, bbb, ccc, X[13], 5);
	GGG(ccc, ddd, eee, aaa, bbb, X[8], 15); GGG(bbb, ccc, ddd, eee, aaa, X[6], 5); GGG(aaa, bbb, ccc, ddd, eee, X[4], 8);
	GGG(eee, aaa, bbb, ccc, ddd, X[1], 11); GGG(ddd, eee, aaa, bbb, ccc, X[3], 14); GGG(ccc, ddd, eee, aaa, bbb, X[11], 14);
	GGG(bbb, ccc, ddd, eee, aaa, X[15], 6); GGG(aaa, bbb, ccc, ddd, eee, X[0], 14); GGG(eee, aaa, bbb, ccc, ddd, X[5], 6);
	GGG(ddd, eee, aaa, bbb, ccc, X[12], 9); GGG(ccc, ddd, eee, aaa, bbb, X[2], 12); GGG(bbb, ccc, ddd, eee, aaa, X[13], 9);
	GGG(aaa, bbb, ccc, ddd, eee, X[9], 12); GGG(eee, aaa, bbb, ccc, ddd, X[7], 5); GGG(ddd, eee, aaa, bbb, ccc, X[10], 15);
	GGG(ccc, ddd, eee, aaa, bbb, X[14], 8);
	FFF(bbb, ccc, ddd, eee, aaa, X[12], 8); FFF(aaa, bbb, ccc, ddd, eee, X[15], 5); FFF(eee, aaa, bbb, ccc, ddd, X[10], 12);
	FFF(ddd, eee, aaa, bbb, ccc, X[4], 9); FFF(ccc, ddd, eee, aaa, bbb, X[1], 12); FFF(bbb, ccc, ddd, eee, aaa, X[5], 5);
	FFF(aaa, bbb, ccc, ddd, eee, X[8], 14); FFF(eee, aaa, bbb, ccc, ddd, X[7], 6); FFF(ddd, eee, aaa, bbb, ccc, X[6], 8);
	FFF(ccc, ddd, eee, aaa, bbb, X[2], 13); FFF(bbb, ccc, ddd, eee, aaa, X[13], 6); FFF(aaa, bbb, ccc, ddd, eee, X[14], 5);
	FFF(eee, aaa, bbb, ccc, ddd, X[0], 15); FFF(ddd, eee, aaa, bbb, ccc, X[3], 13); FFF(ccc, ddd, eee, aaa, bbb, X[9], 11);
	FFF(bbb, ccc, ddd, eee, aaa, X[11], 11);
	ddd += cc + MDbuf[1];
	MDbuf[1] = MDbuf[2] + dd + eee;
	MDbuf[2] = MDbuf[3] + ee + aaa;
	MDbuf[3] = MDbuf[4] + aa + bbb;
	MDbuf[4] = MDbuf[0] + bb + ccc;
	MDbuf[0] = ddd;

	return;
}

void MDfinish(unsigned int *MDbuf, unsigned char *strptr, size_t lswlen, unsigned int mswlen)
{
	unsigned int i, X[16] = { 0, };
	for (i = 0; i<(lswlen & 63); i++) X[i >> 2] ^= (unsigned int)*strptr++ << (8 * (i & 3));

	X[(lswlen >> 2) & 15] ^= (unsigned int)1 << (8 * (lswlen & 3) + 7);

	if ((lswlen & 63) > 55) {
		rmd160_transform(MDbuf, X);
		memset(X, 0, 16 * sizeof(unsigned int));
	}

	X[14] = (unsigned int)lswlen << 3;
	X[15] = (unsigned int)(lswlen >> 29) | (mswlen << 3);
	rmd160_transform(MDbuf, X);

	return;
}

void RIPEMD160(void *bin_in, size_t len, void *bin_out)
{
	unsigned int MDbuf[5], i, X[16];
	size_t nbytes;
	unsigned char *str_in = (unsigned char *)bin_in, *str_out = (unsigned char *)bin_out;

	MDbuf[0] = 0x67452301UL;
	MDbuf[1] = 0xefcdab89UL;
	MDbuf[2] = 0x98badcfeUL;
	MDbuf[3] = 0x10325476UL;
	MDbuf[4] = 0xc3d2e1f0UL;

	for (nbytes = len; nbytes > 63; nbytes -= 64) {
		for (i = 0; i<16; i++) {
			X[i] = BYTES_TO_DWORD(str_in);
			str_in += 4;
		}
		rmd160_transform(MDbuf, X);
	}
	MDfinish(MDbuf, str_in, len, 0);

	for (i = 0; i<20; i += 4) {
		str_out[i] = (unsigned char)MDbuf[i >> 2];
		str_out[i + 1] = (unsigned char)(MDbuf[i >> 2] >> 8);
		str_out[i + 2] = (unsigned char)(MDbuf[i >> 2] >> 16);
		str_out[i + 3] = (unsigned char)(MDbuf[i >> 2] >> 24);
	}
}

void SHA256(void *bin_in, size_t tsize, void *bin_out) {
	sha256_t sha1[32];
	sha256_initialize(sha1);
	sha256_write(sha1, (unsigned char *)bin_in, tsize);
	sha256_finalize(sha1, (unsigned char*)bin_out);
}

void HASH160(void *bin_in, void *bin_out) {
	unsigned char sha[32];
	SHA256(bin_in, 33, sha);
	RIPEMD160(sha, 32, bin_out);
}
void HASH256(void *bin_in, void *bin_out) {
	unsigned char sha[32];
	SHA256(bin_in, 21, sha);
	SHA256(sha, 32, bin_out);
}
