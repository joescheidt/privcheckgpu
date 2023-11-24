#include <stdio.h>

/* Two of six logical functions used in SHA-1, SHA-256, SHA-384, and SHA-512: */
#define SHAF1(x,y,z)	(((x) & (y)) ^ ((~(x)) & (z)))
#define SHAF0(x,y,z)	(((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))



#define mod(x,y) ((x)-((x)/(y)*(y)))
#define shr32(x,n) ((x) >> (n))
#define rotl32(n,d) (((n) << (d)) | ((n) >> (32 - (d))))
#define S0(x) (rotl32 ((x), 25u) ^ rotl32 ((x), 14u) ^ shr32 ((x),  3u))
#define S1(x) (rotl32 ((x), 15u) ^ rotl32 ((x), 13u) ^ shr32 ((x), 10u))
#define S2(x) (rotl32 ((x), 30u) ^ rotl32 ((x), 19u) ^ rotl32 ((x), 10u))
#define S3(x) (rotl32 ((x), 26u) ^ rotl32 ((x), 21u) ^ rotl32 ((x),  7u))


#define highBit(i) (0x0000000000000001ULL << (8*(i) + 7))
#define fBytes(i)  (0xFFFFFFFFFFFFFFFFULL >> (8 * (8-(i))))
#define SHA256C00 0x428a2f98u
#define SHA256C01 0x71374491u
#define SHA256C02 0xb5c0fbcfu
#define SHA256C03 0xe9b5dba5u
#define SHA256C04 0x3956c25bu
#define SHA256C05 0x59f111f1u
#define SHA256C06 0x923f82a4u
#define SHA256C07 0xab1c5ed5u
#define SHA256C08 0xd807aa98u
#define SHA256C09 0x12835b01u
#define SHA256C0a 0x243185beu
#define SHA256C0b 0x550c7dc3u
#define SHA256C0c 0x72be5d74u
#define SHA256C0d 0x80deb1feu
#define SHA256C0e 0x9bdc06a7u
#define SHA256C0f 0xc19bf174u
#define SHA256C10 0xe49b69c1u
#define SHA256C11 0xefbe4786u
#define SHA256C12 0x0fc19dc6u
#define SHA256C13 0x240ca1ccu
#define SHA256C14 0x2de92c6fu
#define SHA256C15 0x4a7484aau
#define SHA256C16 0x5cb0a9dcu
#define SHA256C17 0x76f988dau
#define SHA256C18 0x983e5152u
#define SHA256C19 0xa831c66du
#define SHA256C1a 0xb00327c8u
#define SHA256C1b 0xbf597fc7u
#define SHA256C1c 0xc6e00bf3u
#define SHA256C1d 0xd5a79147u
#define SHA256C1e 0x06ca6351u
#define SHA256C1f 0x14292967u
#define SHA256C20 0x27b70a85u
#define SHA256C21 0x2e1b2138u
#define SHA256C22 0x4d2c6dfcu
#define SHA256C23 0x53380d13u
#define SHA256C24 0x650a7354u
#define SHA256C25 0x766a0abbu
#define SHA256C26 0x81c2c92eu
#define SHA256C27 0x92722c85u
#define SHA256C28 0xa2bfe8a1u
#define SHA256C29 0xa81a664bu
#define SHA256C2a 0xc24b8b70u
#define SHA256C2b 0xc76c51a3u
#define SHA256C2c 0xd192e819u
#define SHA256C2d 0xd6990624u
#define SHA256C2e 0xf40e3585u
#define SHA256C2f 0x106aa070u
#define SHA256C30 0x19a4c116u
#define SHA256C31 0x1e376c08u
#define SHA256C32 0x2748774cu
#define SHA256C33 0x34b0bcb5u
#define SHA256C34 0x391c0cb3u
#define SHA256C35 0x4ed8aa4au
#define SHA256C36 0x5b9cca4fu
#define SHA256C37 0x682e6ff3u
#define SHA256C38 0x748f82eeu
#define SHA256C39 0x78a5636fu
#define SHA256C3a 0x84c87814u
#define SHA256C3b 0x8cc70208u
#define SHA256C3c 0x90befffau
#define SHA256C3d 0xa4506cebu
#define SHA256C3e 0xbef9a3f7u
#define SHA256C3f 0xc67178f2u 


__inline__
__device__
static uint32_t SWAP256(uint32_t val) {
	return (rotl32(((val) & (uint32_t)0x00FF00FF), (uint32_t)24U) | rotl32(((val) & (uint32_t)0xFF00FF00), (uint32_t)8U));
}


// 256 bytes
__constant__ static uint32_t k_sha256[64] =
{
  SHA256C00, SHA256C01, SHA256C02, SHA256C03,
  SHA256C04, SHA256C05, SHA256C06, SHA256C07,
  SHA256C08, SHA256C09, SHA256C0a, SHA256C0b,
  SHA256C0c, SHA256C0d, SHA256C0e, SHA256C0f,
  SHA256C10, SHA256C11, SHA256C12, SHA256C13,
  SHA256C14, SHA256C15, SHA256C16, SHA256C17,
  SHA256C18, SHA256C19, SHA256C1a, SHA256C1b,
  SHA256C1c, SHA256C1d, SHA256C1e, SHA256C1f,
  SHA256C20, SHA256C21, SHA256C22, SHA256C23,
  SHA256C24, SHA256C25, SHA256C26, SHA256C27,
  SHA256C28, SHA256C29, SHA256C2a, SHA256C2b,
  SHA256C2c, SHA256C2d, SHA256C2e, SHA256C2f,
  SHA256C30, SHA256C31, SHA256C32, SHA256C33,
  SHA256C34, SHA256C35, SHA256C36, SHA256C37,
  SHA256C38, SHA256C39, SHA256C3a, SHA256C3b,
  SHA256C3c, SHA256C3d, SHA256C3e, SHA256C3f,
};

#define SHA256_STEP(F0a,F1a,a,b,c,d,e,f,g,h,x,K) { h += K; h += x; h += S3 (e); h += F1a (e,f,g); d += h; h += S2 (a); h += F0a (a,b,c); }
#define SHA256_EXPAND(x,y,z,w) (S1 (x) + y + S0 (z) + w) 


__device__
static void sha256_process2(const uint32_t* W, uint32_t* digest) {
	uint32_t a = digest[0];
	uint32_t b = digest[1];
	uint32_t c = digest[2];
	uint32_t d = digest[3];
	uint32_t e = digest[4];
	uint32_t f = digest[5];
	uint32_t g = digest[6];
	uint32_t h = digest[7];

	uint32_t w0_t = W[0];
	uint32_t w1_t = W[1];
	uint32_t w2_t = W[2];
	uint32_t w3_t = W[3];
	uint32_t w4_t = W[4];
	uint32_t w5_t = W[5];
	uint32_t w6_t = W[6];
	uint32_t w7_t = W[7];
	uint32_t w8_t = W[8];
	uint32_t w9_t = W[9];
	uint32_t wa_t = W[10];
	uint32_t wb_t = W[11];
	uint32_t wc_t = W[12];
	uint32_t wd_t = W[13];
	uint32_t we_t = W[14];
	uint32_t wf_t = W[15];

#define ROUND_EXPAND() { w0_t = SHA256_EXPAND (we_t, w9_t, w1_t, w0_t); w1_t = SHA256_EXPAND (wf_t, wa_t, w2_t, w1_t); w2_t = SHA256_EXPAND (w0_t, wb_t, w3_t, w2_t); w3_t = SHA256_EXPAND (w1_t, wc_t, w4_t, w3_t); w4_t = SHA256_EXPAND (w2_t, wd_t, w5_t, w4_t); w5_t = SHA256_EXPAND (w3_t, we_t, w6_t, w5_t); w6_t = SHA256_EXPAND (w4_t, wf_t, w7_t, w6_t); w7_t = SHA256_EXPAND (w5_t, w0_t, w8_t, w7_t); w8_t = SHA256_EXPAND (w6_t, w1_t, w9_t, w8_t); w9_t = SHA256_EXPAND (w7_t, w2_t, wa_t, w9_t); wa_t = SHA256_EXPAND (w8_t, w3_t, wb_t, wa_t); wb_t = SHA256_EXPAND (w9_t, w4_t, wc_t, wb_t); wc_t = SHA256_EXPAND (wa_t, w5_t, wd_t, wc_t); wd_t = SHA256_EXPAND (wb_t, w6_t, we_t, wd_t); we_t = SHA256_EXPAND (wc_t, w7_t, wf_t, we_t); wf_t = SHA256_EXPAND (wd_t, w8_t, w0_t, wf_t); }
#define ROUND_STEP(i) { SHA256_STEP (SHAF0, SHAF1, a, b, c, d, e, f, g, h, w0_t, k_sha256[i +  0]); SHA256_STEP (SHAF0, SHAF1, h, a, b, c, d, e, f, g, w1_t, k_sha256[i +  1]); SHA256_STEP (SHAF0, SHAF1, g, h, a, b, c, d, e, f, w2_t, k_sha256[i +  2]); SHA256_STEP (SHAF0, SHAF1, f, g, h, a, b, c, d, e, w3_t, k_sha256[i +  3]); SHA256_STEP (SHAF0, SHAF1, e, f, g, h, a, b, c, d, w4_t, k_sha256[i +  4]); SHA256_STEP (SHAF0, SHAF1, d, e, f, g, h, a, b, c, w5_t, k_sha256[i +  5]); SHA256_STEP (SHAF0, SHAF1, c, d, e, f, g, h, a, b, w6_t, k_sha256[i +  6]); SHA256_STEP (SHAF0, SHAF1, b, c, d, e, f, g, h, a, w7_t, k_sha256[i +  7]); SHA256_STEP (SHAF0, SHAF1, a, b, c, d, e, f, g, h, w8_t, k_sha256[i +  8]); SHA256_STEP (SHAF0, SHAF1, h, a, b, c, d, e, f, g, w9_t, k_sha256[i +  9]); SHA256_STEP (SHAF0, SHAF1, g, h, a, b, c, d, e, f, wa_t, k_sha256[i + 10]); SHA256_STEP (SHAF0, SHAF1, f, g, h, a, b, c, d, e, wb_t, k_sha256[i + 11]); SHA256_STEP (SHAF0, SHAF1, e, f, g, h, a, b, c, d, wc_t, k_sha256[i + 12]); SHA256_STEP (SHAF0, SHAF1, d, e, f, g, h, a, b, c, wd_t, k_sha256[i + 13]); SHA256_STEP (SHAF0, SHAF1, c, d, e, f, g, h, a, b, we_t, k_sha256[i + 14]); SHA256_STEP (SHAF0, SHAF1, b, c, d, e, f, g, h, a, wf_t, k_sha256[i + 15]); }

	ROUND_STEP(0);
	ROUND_EXPAND();
	ROUND_STEP(16);
	ROUND_EXPAND();
	ROUND_STEP(32);
	ROUND_EXPAND();
	ROUND_STEP(48);

	digest[0] += a;
	digest[1] += b;
	digest[2] += c;
	digest[3] += d;
	digest[4] += e;
	digest[5] += f;
	digest[6] += g;
	digest[7] += h;
}

__device__
static void sha256(const uint32_t* pass, int pass_len, uint32_t* hash) {
	int plen = pass_len / 4;
	if (mod(pass_len, 4)) plen++;
	uint32_t* p = hash;
	uint32_t W[0x10];
	int loops = plen;
	int curloop = 0;
	uint32_t State[8];
	State[0] = 0x6a09e667;
	State[1] = 0xbb67ae85;
	State[2] = 0x3c6ef372;
	State[3] = 0xa54ff53a;
	State[4] = 0x510e527f;
	State[5] = 0x9b05688c;
	State[6] = 0x1f83d9ab;
	State[7] = 0x5be0cd19;
	while (loops > 0) {
		W[0x0] = 0x0;
		W[0x1] = 0x0;
		W[0x2] = 0x0;
		W[0x3] = 0x0;
		W[0x4] = 0x0;
		W[0x5] = 0x0;
		W[0x6] = 0x0;
		W[0x7] = 0x0;
		W[0x8] = 0x0;
		W[0x9] = 0x0;
		W[0xA] = 0x0;
		W[0xB] = 0x0;
		W[0xC] = 0x0;
		W[0xD] = 0x0;
		W[0xE] = 0x0;
		W[0xF] = 0x0;
		for (int m = 0; loops != 0 && m < 16; m++) {
			W[m] ^= SWAP256(pass[m + (curloop * 16)]);
			loops--;
		}
		if (loops == 0 && mod(pass_len, 64) != 0) {
			uint32_t padding = 0x80 << (((pass_len + 4) - ((pass_len + 4) / 4 * 4)) * 8);
			int v = mod(pass_len, 64);
			W[v / 4] |= SWAP256(padding);
			if ((pass_len & 0x3B) != 0x3B) {
				W[0x0F] = pass_len * 8;
			}
		}
		sha256_process2(W, State);
		curloop++;
	}
	if (mod(plen, 16) == 0) {
		W[0x0] = 0x0;
		W[0x1] = 0x0;
		W[0x2] = 0x0;
		W[0x3] = 0x0;
		W[0x4] = 0x0;
		W[0x5] = 0x0;
		W[0x6] = 0x0;
		W[0x7] = 0x0;
		W[0x8] = 0x0;
		W[0x9] = 0x0;
		W[0xA] = 0x0;
		W[0xB] = 0x0;
		W[0xC] = 0x0;
		W[0xD] = 0x0;
		W[0xE] = 0x0;
		W[0xF] = 0x0;
		if ((pass_len & 0x3B) != 0x3B) {
			uint32_t padding = 0x80 << (((pass_len + 4) - ((pass_len + 4) / 4 * 4)) * 8);
			W[0] |= SWAP256(padding);
		}
		W[0x0F] = pass_len * 8;
		sha256_process2(W, State);
	}
	p[0] = SWAP256(State[0]);
	p[1] = SWAP256(State[1]);
	p[2] = SWAP256(State[2]);
	p[3] = SWAP256(State[3]);
	p[4] = SWAP256(State[4]);
	p[5] = SWAP256(State[5]);
	p[6] = SWAP256(State[6]);
	p[7] = SWAP256(State[7]);
	return;
}

typedef struct {
	uint32_t total[2];
	uint32_t state[5];
	uint8_t buffer[64];
} RIPEMD160_CTX;

#define GET_UINT32_LE(n,b,i) { (n) = ( (uint32_t) (b)[(i)])| ( (uint32_t) (b)[(i) + 1] <<  8 )| ( (uint32_t) (b)[(i) + 2] << 16 ) | ( (uint32_t) (b)[(i) + 3] << 24 );}

#define PUT_UINT32_LE(n,b,i) { (b)[(i)    ] = (uint8_t) ( ( (n)       ) & 0xFF ); (b)[(i) + 1] = (uint8_t) ( ( (n) >>  8 ) & 0xFF ); (b)[(i) + 2] = (uint8_t) ( ( (n) >> 16 ) & 0xFF ); (b)[(i) + 3] = (uint8_t) ( ( (n) >> 24 ) & 0xFF ); }
__device__
void ripemd160_Init(RIPEMD160_CTX* ctx)
{
	//memset((uint8_t*)ctx, 0, sizeof(RIPEMD160_CTX));
	for (int i = 0; i < 64 / 4; i++)
	{
		*(uint32_t*)((uint32_t*)ctx->buffer + i) = 0;
	}
	ctx->total[0] = 0;
	ctx->total[1] = 0;
	ctx->state[0] = 0x67452301;
	ctx->state[1] = 0xEFCDAB89;
	ctx->state[2] = 0x98BADCFE;
	ctx->state[3] = 0x10325476;
	ctx->state[4] = 0xC3D2E1F0;
}
__device__
void ripemd160_process(RIPEMD160_CTX* ctx, const uint8_t data[64])
{
	uint32_t A, B, C, D, E, Ap, Bp, Cp, Dp, Ep, X[16];

	GET_UINT32_LE(X[0], data, 0);
	GET_UINT32_LE(X[1], data, 4);
	GET_UINT32_LE(X[2], data, 8);
	GET_UINT32_LE(X[3], data, 12);
	GET_UINT32_LE(X[4], data, 16);
	GET_UINT32_LE(X[5], data, 20);
	GET_UINT32_LE(X[6], data, 24);
	GET_UINT32_LE(X[7], data, 28);
	GET_UINT32_LE(X[8], data, 32);
	GET_UINT32_LE(X[9], data, 36);
	GET_UINT32_LE(X[10], data, 40);
	GET_UINT32_LE(X[11], data, 44);
	GET_UINT32_LE(X[12], data, 48);
	GET_UINT32_LE(X[13], data, 52);
	GET_UINT32_LE(X[14], data, 56);
	GET_UINT32_LE(X[15], data, 60);

	A = Ap = ctx->state[0];
	B = Bp = ctx->state[1];
	C = Cp = ctx->state[2];
	D = Dp = ctx->state[3];
	E = Ep = ctx->state[4];

#define F1( x, y, z )   ( x ^ y ^ z )
#define F2( x, y, z )   ( ( x & y ) | ( ~x & z ) )
#define F3( x, y, z )   ( ( x | ~y ) ^ z )
#define F4( x, y, z )   ( ( x & z ) | ( y & ~z ) )
#define F5( x, y, z )   ( x ^ ( y | ~z ) )

#define S( x, n ) ( ( x << n ) | ( x >> (32 - n) ) )

#define P( a, b, c, d, e, r, s, f, k ) { a += f( b, c, d ) + X[r] + k; a = S( a, s ) + e; c = S( c, 10 ); }
#define P2( a, b, c, d, e, r, s, rp, sp ) { P( a, b, c, d, e, r, s, F, K ); P( a ## p, b ## p, c ## p, d ## p, e ## p, rp, sp, Fp, Kp ); }


#define F   F1
#define K   0x00000000
#define Fp  F5
#define Kp  0x50A28BE6
	P2(A, B, C, D, E, 0, 11, 5, 8);
	P2(E, A, B, C, D, 1, 14, 14, 9);
	P2(D, E, A, B, C, 2, 15, 7, 9);
	P2(C, D, E, A, B, 3, 12, 0, 11);
	P2(B, C, D, E, A, 4, 5, 9, 13);
	P2(A, B, C, D, E, 5, 8, 2, 15);
	P2(E, A, B, C, D, 6, 7, 11, 15);
	P2(D, E, A, B, C, 7, 9, 4, 5);
	P2(C, D, E, A, B, 8, 11, 13, 7);
	P2(B, C, D, E, A, 9, 13, 6, 7);
	P2(A, B, C, D, E, 10, 14, 15, 8);
	P2(E, A, B, C, D, 11, 15, 8, 11);
	P2(D, E, A, B, C, 12, 6, 1, 14);
	P2(C, D, E, A, B, 13, 7, 10, 14);
	P2(B, C, D, E, A, 14, 9, 3, 12);
	P2(A, B, C, D, E, 15, 8, 12, 6);
#undef F
#undef K
#undef Fp
#undef Kp

#define F   F2
#define K   0x5A827999
#define Fp  F4
#define Kp  0x5C4DD124
	P2(E, A, B, C, D, 7, 7, 6, 9);
	P2(D, E, A, B, C, 4, 6, 11, 13);
	P2(C, D, E, A, B, 13, 8, 3, 15);
	P2(B, C, D, E, A, 1, 13, 7, 7);
	P2(A, B, C, D, E, 10, 11, 0, 12);
	P2(E, A, B, C, D, 6, 9, 13, 8);
	P2(D, E, A, B, C, 15, 7, 5, 9);
	P2(C, D, E, A, B, 3, 15, 10, 11);
	P2(B, C, D, E, A, 12, 7, 14, 7);
	P2(A, B, C, D, E, 0, 12, 15, 7);
	P2(E, A, B, C, D, 9, 15, 8, 12);
	P2(D, E, A, B, C, 5, 9, 12, 7);
	P2(C, D, E, A, B, 2, 11, 4, 6);
	P2(B, C, D, E, A, 14, 7, 9, 15);
	P2(A, B, C, D, E, 11, 13, 1, 13);
	P2(E, A, B, C, D, 8, 12, 2, 11);
#undef F
#undef K
#undef Fp
#undef Kp

#define F   F3
#define K   0x6ED9EBA1
#define Fp  F3
#define Kp  0x6D703EF3
	P2(D, E, A, B, C, 3, 11, 15, 9);
	P2(C, D, E, A, B, 10, 13, 5, 7);
	P2(B, C, D, E, A, 14, 6, 1, 15);
	P2(A, B, C, D, E, 4, 7, 3, 11);
	P2(E, A, B, C, D, 9, 14, 7, 8);
	P2(D, E, A, B, C, 15, 9, 14, 6);
	P2(C, D, E, A, B, 8, 13, 6, 6);
	P2(B, C, D, E, A, 1, 15, 9, 14);
	P2(A, B, C, D, E, 2, 14, 11, 12);
	P2(E, A, B, C, D, 7, 8, 8, 13);
	P2(D, E, A, B, C, 0, 13, 12, 5);
	P2(C, D, E, A, B, 6, 6, 2, 14);
	P2(B, C, D, E, A, 13, 5, 10, 13);
	P2(A, B, C, D, E, 11, 12, 0, 13);
	P2(E, A, B, C, D, 5, 7, 4, 7);
	P2(D, E, A, B, C, 12, 5, 13, 5);
#undef F
#undef K
#undef Fp
#undef Kp

#define F   F4
#define K   0x8F1BBCDC
#define Fp  F2
#define Kp  0x7A6D76E9
	P2(C, D, E, A, B, 1, 11, 8, 15);
	P2(B, C, D, E, A, 9, 12, 6, 5);
	P2(A, B, C, D, E, 11, 14, 4, 8);
	P2(E, A, B, C, D, 10, 15, 1, 11);
	P2(D, E, A, B, C, 0, 14, 3, 14);
	P2(C, D, E, A, B, 8, 15, 11, 14);
	P2(B, C, D, E, A, 12, 9, 15, 6);
	P2(A, B, C, D, E, 4, 8, 0, 14);
	P2(E, A, B, C, D, 13, 9, 5, 6);
	P2(D, E, A, B, C, 3, 14, 12, 9);
	P2(C, D, E, A, B, 7, 5, 2, 12);
	P2(B, C, D, E, A, 15, 6, 13, 9);
	P2(A, B, C, D, E, 14, 8, 9, 12);
	P2(E, A, B, C, D, 5, 6, 7, 5);
	P2(D, E, A, B, C, 6, 5, 10, 15);
	P2(C, D, E, A, B, 2, 12, 14, 8);
#undef F
#undef K
#undef Fp
#undef Kp

#define F   F5
#define K   0xA953FD4E
#define Fp  F1
#define Kp  0x00000000
	P2(B, C, D, E, A, 4, 9, 12, 8);
	P2(A, B, C, D, E, 0, 15, 15, 5);
	P2(E, A, B, C, D, 5, 5, 10, 12);
	P2(D, E, A, B, C, 9, 11, 4, 9);
	P2(C, D, E, A, B, 7, 6, 1, 12);
	P2(B, C, D, E, A, 12, 8, 5, 5);
	P2(A, B, C, D, E, 2, 13, 8, 14);
	P2(E, A, B, C, D, 10, 12, 7, 6);
	P2(D, E, A, B, C, 14, 5, 6, 8);
	P2(C, D, E, A, B, 1, 12, 2, 13);
	P2(B, C, D, E, A, 3, 13, 13, 6);
	P2(A, B, C, D, E, 8, 14, 14, 5);
	P2(E, A, B, C, D, 11, 11, 0, 15);
	P2(D, E, A, B, C, 6, 8, 3, 13);
	P2(C, D, E, A, B, 15, 5, 9, 11);
	P2(B, C, D, E, A, 13, 6, 11, 11);
#undef F
#undef K
#undef Fp
#undef Kp

	C = ctx->state[1] + C + Dp;
	ctx->state[1] = ctx->state[2] + D + Ep;
	ctx->state[2] = ctx->state[3] + E + Ap;
	ctx->state[3] = ctx->state[4] + A + Bp;
	ctx->state[4] = ctx->state[0] + B + Cp;
	ctx->state[0] = C;
}
__device__
void ripemd160_Update(RIPEMD160_CTX* ctx, const uint8_t* input, uint32_t ilen)
{
	uint32_t fill;
	uint32_t left;

	if (ilen == 0)
		return;

	left = ctx->total[0] & 0x3F;
	fill = 64 - left;

	ctx->total[0] += (uint32_t)ilen;
	ctx->total[0] &= 0xFFFFFFFF;

	if (ctx->total[0] < (uint32_t)ilen)
		ctx->total[1]++;

	if (left && ilen >= fill)
	{
		memcpy((uint8_t*)(ctx->buffer + left), input, fill);

		ripemd160_process(ctx, ctx->buffer);
		input += fill;
		ilen -= fill;
		left = 0;
	}

	while (ilen >= 64)
	{
		ripemd160_process(ctx, input);
		input += 64;
		ilen -= 64;
	}

	if (ilen > 0)
	{
		memcpy((uint8_t*)(ctx->buffer + left), input, ilen);
	}
}

__constant__ uint8_t ripemd160_padding[64] = {
0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

__device__
void ripemd160_Final(RIPEMD160_CTX* ctx, uint32_t output[5])
{
	uint32_t last, padn;
	uint32_t high, low;
	uint8_t msglen[8];

	high = (ctx->total[0] >> 29)
		| (ctx->total[1] << 3);
	low = (ctx->total[0] << 3);

	PUT_UINT32_LE(low, msglen, 0);
	PUT_UINT32_LE(high, msglen, 4);

	last = ctx->total[0] & 0x3F;
	padn = (last < 56) ? (56 - last) : (120 - last);


	ripemd160_Update(ctx, ripemd160_padding, padn);
	ripemd160_Update(ctx, msglen, 8);

	output[0] = ctx->state[0];
	output[1] = ctx->state[1];
	output[2] = ctx->state[2];
	output[3] = ctx->state[3];
	output[4] = ctx->state[4];
}
__device__
void ripemd160_GPU(const uint8_t* msg, uint32_t msg_len, uint32_t hash[5])
{
	RIPEMD160_CTX ctx;
	ripemd160_Init(&ctx);
	ripemd160_Update(&ctx, msg, msg_len);
	ripemd160_Final(&ctx, hash);
}

__device__
void hash160(const uint8_t* input, int input_len, uint32_t* output) {
	uint8_t sha256_result[32];
	sha256((const uint32_t*)input, input_len, (uint32_t*)&sha256_result);
	ripemd160_GPU((const uint8_t*)&sha256_result, 32, output);
}

