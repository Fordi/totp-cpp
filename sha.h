#ifndef SHA_H
#define SHA_H

#include <array>
#include <cctype>
#include <vector>

std::array<uint8_t, 20> sha1(const std::vector<uint8_t>& msg);
std::array<uint8_t, 32> sha256(const std::vector<uint8_t>& msg);
std::array<uint8_t, 64> sha512(const std::vector<uint8_t>& msg);

std::array<uint8_t, 20> hmac_sha1(const std::vector<uint8_t>& key, const std::vector<uint8_t>& msg);
std::array<uint8_t, 32> hmac_sha256(const std::vector<uint8_t>& key, const std::vector<uint8_t>& msg);
std::array<uint8_t, 64> hmac_sha512(const std::vector<uint8_t>& key, const std::vector<uint8_t>& msg);

#endif