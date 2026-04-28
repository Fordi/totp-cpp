#include <cstdint>
#include <string>
#include <vector>
#include "./base32_decode.h"


std::vector<uint8_t> base32_decode(const std::string& s) {
  static const std::string alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  std::vector<uint8_t> result;
  uint32_t buf = 0;
  int bits = 0;
  for (char c : s) {
    if (c == '=') break;
    size_t val = alpha.find(toupper(c));
    if (val == std::string::npos) continue;
    buf = (buf << 5) | val;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      result.push_back((buf >> bits) & 0xFF);
    }
  }
  return result;
}