/*  Copyright (c) 2015 Ryan Castellucci, All Rights Reserved */

#ifndef _BLOOM_H
#define _BLOOM_H
/* bloom filter */
/* 2^32 bits */
#define BLOOM_SIZE (512 * 1024 * 1024)

#define BLOOM_SET_BIT(N) (bloom[(N) >> 3] = bloom[(N) >> 3] | (1 << ((N)&7)))
#define BLOOM_GET_BIT(N) (((bloom[(N) >> 3]) >> ((N)&7)) & 1)

#define BH00(N) (N[0])
#define BH01(N) (N[1])
#define BH02(N) (N[2])
#define BH03(N) (N[3])
#define BH04(N) (N[4])

#define BH05(N) (N[0] << 16 | N[1] >> 16)
#define BH06(N) (N[1] << 16 | N[2] >> 16)
#define BH07(N) (N[2] << 16 | N[3] >> 16)
#define BH08(N) (N[3] << 16 | N[4] >> 16)
#define BH09(N) (N[4] << 16 | N[0] >> 16)

#define BH10(N) (N[0] << 8 | N[1] >> 24)
#define BH11(N) (N[1] << 8 | N[2] >> 24)
#define BH12(N) (N[2] << 8 | N[3] >> 24)
#define BH13(N) (N[3] << 8 | N[4] >> 24)
#define BH14(N) (N[4] << 8 | N[0] >> 24)

#define BH15(N) (N[0] << 24 | N[1] >> 8)
#define BH16(N) (N[1] << 24 | N[2] >> 8)
#define BH17(N) (N[2] << 24 | N[3] >> 8)
#define BH18(N) (N[3] << 24 | N[4] >> 8)
#define BH19(N) (N[4] << 24 | N[0] >> 8)


__device__ __forceinline__ bool bloom_chk_hash160(const unsigned char *bloom, uint32_t *h) {
  unsigned int t;
  t = BH00(h); if (BLOOM_GET_BIT(t) == 0) { return false; }
  t = BH01(h); if (BLOOM_GET_BIT(t) == 0) { return false; }
  t = BH02(h); if (BLOOM_GET_BIT(t) == 0) { return false; }
  t = BH03(h); if (BLOOM_GET_BIT(t) == 0) { return false; }
  t = BH04(h); if (BLOOM_GET_BIT(t) == 0) { return false; }
  t = BH05(h); if (BLOOM_GET_BIT(t) == 0) { return false; }
  t = BH06(h); if (BLOOM_GET_BIT(t) == 0) { return false; }
  t = BH07(h); if (BLOOM_GET_BIT(t) == 0) { return false; }
  t = BH08(h); if (BLOOM_GET_BIT(t) == 0) { return false; }
  t = BH09(h); if (BLOOM_GET_BIT(t) == 0) { return false; }
  t = BH10(h); if (BLOOM_GET_BIT(t) == 0) { return false; }
  t = BH11(h); if (BLOOM_GET_BIT(t) == 0) { return false; }
  t = BH12(h); if (BLOOM_GET_BIT(t) == 0) { return false; }
  t = BH13(h); if (BLOOM_GET_BIT(t) == 0) { return false; }
  t = BH14(h); if (BLOOM_GET_BIT(t) == 0) { return false; }
  t = BH15(h); if (BLOOM_GET_BIT(t) == 0) { return false; }
  t = BH16(h); if (BLOOM_GET_BIT(t) == 0) { return false; }
  t = BH17(h); if (BLOOM_GET_BIT(t) == 0) { return false; }
  t = BH18(h); if (BLOOM_GET_BIT(t) == 0) { return false; }
  t = BH19(h); if (BLOOM_GET_BIT(t) == 0) { return false; }
  return true;
}
#endif