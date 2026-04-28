#include <array>
#include <cstdint>
#include <vector>
#include "./sha.h"

std::array<uint8_t, 20> sha1(const std::vector<uint8_t>& msg) {
  auto rotl = [](uint32_t x, int n) { return (x << n) | (x >> (32 - n)); };

  uint32_t h0 = 0x67452301, h1 = 0xEFCDAB89, h2 = 0x98BADCFE,
           h3 = 0x10325476, h4 = 0xC3D2E1F0;

  // pad message: append 0x80, zeros, then 64-bit big-endian bit length
  std::vector<uint8_t> m(msg);
  uint64_t bit_len = msg.size() * 8;
  m.push_back(0x80);
  while (m.size() % 64 != 56) m.push_back(0x00);
  for (int i = 7; i >= 0; --i) m.push_back((bit_len >> (i * 8)) & 0xFF);

  for (size_t off = 0; off < m.size(); off += 64) {
    uint32_t w[80];
    for (int i = 0; i < 16; ++i)
      w[i] = (m[off+i*4]<<24)|(m[off+i*4+1]<<16)|(m[off+i*4+2]<<8)|m[off+i*4+3];
    for (int i = 16; i < 80; ++i)
      w[i] = rotl(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);

    uint32_t a = h0, b = h1, c = h2, d = h3, e = h4;
    for (int i = 0; i < 80; ++i) {
      uint32_t f, k;
      if      (i < 20) { f = (b & c) | (~b & d); k = 0x5A827999; }
      else if (i < 40) { f = b ^ c ^ d;           k = 0x6ED9EBA1; }
      else if (i < 60) { f = (b & c)|(b & d)|(c & d); k = 0x8F1BBCDC; }
      else             { f = b ^ c ^ d;           k = 0xCA62C1D6; }
      uint32_t t = rotl(a, 5) + f + e + k + w[i];
      e = d; d = c; c = rotl(b, 30); b = a; a = t;
    }
    h0 += a; h1 += b; h2 += c; h3 += d; h4 += e;
  }

  std::array<uint8_t, 20> digest;
  for (int i = 0; i < 4; ++i) {
    digest[i]    = (h0 >> (24 - i*8)) & 0xFF;
    digest[4+i]  = (h1 >> (24 - i*8)) & 0xFF;
    digest[8+i]  = (h2 >> (24 - i*8)) & 0xFF;
    digest[12+i] = (h3 >> (24 - i*8)) & 0xFF;
    digest[16+i] = (h4 >> (24 - i*8)) & 0xFF;
  }
  return digest;
}

std::array<uint8_t, 32> sha256(const std::vector<uint8_t>& msg) {
  auto rotr = [](uint32_t x, int n) { return (x >> n) | (x << (32 - n)); };

  static const uint32_t k[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
  };

  uint32_t h[8] = {
    0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
    0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19
  };

  std::vector<uint8_t> m(msg);
  uint64_t bit_len = msg.size() * 8;
  m.push_back(0x80);
  while (m.size() % 64 != 56) m.push_back(0x00);
  for (int i = 7; i >= 0; --i) m.push_back((bit_len >> (i * 8)) & 0xFF);

  for (size_t off = 0; off < m.size(); off += 64) {
    uint32_t w[64];
    for (int i = 0; i < 16; ++i)
      w[i] = (m[off+i*4]<<24)|(m[off+i*4+1]<<16)|(m[off+i*4+2]<<8)|m[off+i*4+3];
    for (int i = 16; i < 64; ++i) {
      uint32_t s0 = rotr(w[i-15],7)  ^ rotr(w[i-15],18) ^ (w[i-15]>>3);
      uint32_t s1 = rotr(w[i-2], 17) ^ rotr(w[i-2], 19) ^ (w[i-2]>>10);
      w[i] = w[i-16] + s0 + w[i-7] + s1;
    }

    uint32_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
    for (int i = 0; i < 64; ++i) {
      uint32_t S1  = rotr(e,6) ^ rotr(e,11) ^ rotr(e,25);
      uint32_t ch  = (e & f) ^ (~e & g);
      uint32_t t1  = hh + S1 + ch + k[i] + w[i];
      uint32_t S0  = rotr(a,2) ^ rotr(a,13) ^ rotr(a,22);
      uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
      uint32_t t2  = S0 + maj;
      hh=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d; h[4]+=e; h[5]+=f; h[6]+=g; h[7]+=hh;
  }

  std::array<uint8_t, 32> digest;
  for (int i = 0; i < 8; ++i)
    for (int j = 0; j < 4; ++j)
      digest[i*4+j] = (h[i] >> (24 - j*8)) & 0xFF;
  return digest;
}

std::array<uint8_t, 64> sha512(const std::vector<uint8_t>& msg) {
  auto rotr = [](uint64_t x, int n) { return (x >> n) | (x << (64 - n)); };

  static const uint64_t k[80] = {
    0x428a2f98d728ae22,0x7137449123ef65cd,0xb5c0fbcfec4d3b2f,0xe9b5dba58189dbbc,
    0x3956c25bf348b538,0x59f111f1b605d019,0x923f82a4af194f9b,0xab1c5ed5da6d8118,
    0xd807aa98a3030242,0x12835b0145706fbe,0x243185be4ee4b28c,0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f,0x80deb1fe3b1696b1,0x9bdc06a725c71235,0xc19bf174cf692694,
    0xe49b69c19ef14ad2,0xefbe4786384f25e3,0x0fc19dc68b8cd5b5,0x240ca1cc77ac9c65,
    0x2de92c6f592b0275,0x4a7484aa6ea6e483,0x5cb0a9dcbd41fbd4,0x76f988da831153b5,
    0x983e5152ee66dfab,0xa831c66d2db43210,0xb00327c898fb213f,0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2,0xd5a79147930aa725,0x06ca6351e003826f,0x142929670a0e6e70,
    0x27b70a8546d22ffc,0x2e1b21385c26c926,0x4d2c6dfc5ac42aed,0x53380d139d95b3df,
    0x650a73548baf63de,0x766a0abb3c77b2a8,0x81c2c92e47edaee6,0x92722c851482353b,
    0xa2bfe8a14cf10364,0xa81a664bbc423001,0xc24b8b70d0f89791,0xc76c51a30654be30,
    0xd192e819d6ef5218,0xd69906245565a910,0xf40e35855771202a,0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8,0x1e376c085141ab53,0x2748774cdf8eeb99,0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63,0x4ed8aa4ae3418acb,0x5b9cca4f7763e373,0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc,0x78a5636f43172f60,0x84c87814a1f0ab72,0x8cc702081a6439ec,
    0x90befffa23631e28,0xa4506cebde82bde9,0xbef9a3f7b2c67915,0xc67178f2e372532b,
    0xca273eceea26619c,0xd186b8c721c0c207,0xeada7dd6cde0eb1e,0xf57d4f7fee6ed178,
    0x06f067aa72176fba,0x0a637dc5a2c898a6,0x113f9804bef90dae,0x1b710b35131c471b,
    0x28db77f523047d84,0x32caab7b40c72493,0x3c9ebe0a15c9bebc,0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6,0x597f299cfc657e2a,0x5fcb6fab3ad6faec,0x6c44198c4a475817
  };

  uint64_t h[8] = {
    0x6a09e667f3bcc908,0xbb67ae8584caa73b,0x3c6ef372fe94f82b,0xa54ff53a5f1d36f1,
    0x510e527fade682d1,0x9b05688c2b3e6c1f,0x1f83d9abfb41bd6b,0x5be0cd19137e2179
  };

  std::vector<uint8_t> m(msg);
  uint64_t bit_len = msg.size() * 8;
  m.push_back(0x80);
  while (m.size() % 128 != 112) m.push_back(0x00);
  for (int i = 7; i >= 0; --i) m.push_back(0x00); // high 64 bits of length always 0
  for (int i = 7; i >= 0; --i) m.push_back((bit_len >> (i * 8)) & 0xFF);

  for (size_t off = 0; off < m.size(); off += 128) {
    uint64_t w[80];
    for (int i = 0; i < 16; ++i) {
      w[i] = 0;
      for (int j = 0; j < 8; ++j)
        w[i] = (w[i] << 8) | m[off + i*8 + j];
    }
    for (int i = 16; i < 80; ++i) {
      uint64_t s0 = rotr(w[i-15],1)  ^ rotr(w[i-15],8)  ^ (w[i-15]>>7);
      uint64_t s1 = rotr(w[i-2], 19) ^ rotr(w[i-2], 61) ^ (w[i-2]>>6);
      w[i] = w[i-16] + s0 + w[i-7] + s1;
    }

    uint64_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
    for (int i = 0; i < 80; ++i) {
      uint64_t S1  = rotr(e,14) ^ rotr(e,18) ^ rotr(e,41);
      uint64_t ch  = (e & f) ^ (~e & g);
      uint64_t t1  = hh + S1 + ch + k[i] + w[i];
      uint64_t S0  = rotr(a,28) ^ rotr(a,34) ^ rotr(a,39);
      uint64_t maj = (a & b) ^ (a & c) ^ (b & c);
      uint64_t t2  = S0 + maj;
      hh=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d; h[4]+=e; h[5]+=f; h[6]+=g; h[7]+=hh;
  }

  std::array<uint8_t, 64> digest;
  for (int i = 0; i < 8; ++i)
    for (int j = 0; j < 8; ++j)
      digest[i*8+j] = (h[i] >> (56 - j*8)) & 0xFF;
  return digest;
}

template<size_t DigestSize, size_t BlockSize, typename HashFn>

std::array<uint8_t, DigestSize> hmac(HashFn hash_fn, const std::vector<uint8_t>& key, const std::vector<uint8_t>& msg) {
  std::vector<uint8_t> k;
  if (key.size() > BlockSize) {
    auto hk = hash_fn(key);
    k.assign(hk.begin(), hk.end());
  } else {
    k = key;
  }
  k.resize(BlockSize, 0x00);

  std::vector<uint8_t> ipad(k), opad(k);
  for (size_t i = 0; i < BlockSize; ++i) { ipad[i] ^= 0x36; opad[i] ^= 0x5c; }

  std::vector<uint8_t> inner(ipad);
  inner.insert(inner.end(), msg.begin(), msg.end());
  auto inner_hash = hash_fn(inner);

  std::vector<uint8_t> outer(opad);
  outer.insert(outer.end(), inner_hash.begin(), inner_hash.end());
  return hash_fn(outer);
}

std::array<uint8_t, 20> hmac_sha1(const std::vector<uint8_t>& key, const std::vector<uint8_t>& msg) {
  return hmac<20, 64>(sha1, key, msg);
}

std::array<uint8_t, 32> hmac_sha256(const std::vector<uint8_t>& key, const std::vector<uint8_t>& msg) {
  return hmac<32, 64>(sha256, key, msg);
}

std::array<uint8_t, 64> hmac_sha512(const std::vector<uint8_t>& key, const std::vector<uint8_t>& msg) {
  return hmac<64, 128>(sha512, key, msg);
}
