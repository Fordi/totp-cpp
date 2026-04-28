#ifndef BASE32_DECODE_H
#define BASE32_DECODE_H

#include <cstdint>
#include <string>
#include <vector>

std::vector<uint8_t> base32_decode(const std::string& s);

#endif