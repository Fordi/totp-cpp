#include <regex>

#include <array>
#include <cstdint>
#include <cstdlib>
#include <ctime>
#include <iostream>
#include <cmath>

#include "./TOTP.h"
#include "./url_decode.h"
#include "./base32_decode.h"
#include "./sha.h"

std::vector<uint8_t> hmac_totp(const std::string& algorithm, const std::vector<uint8_t>& key, const std::vector<uint8_t>& msg) {
  if (algorithm == "SHA256") {
    auto h = hmac_sha256(key, msg);
    return {h.begin(), h.end()};
  }
  if (algorithm == "SHA512") {
    auto h = hmac_sha512(key, msg);
    return {h.begin(), h.end()};
  }
  auto h = hmac_sha1(key, msg);
  return {h.begin(), h.end()};
}

std::array<uint8_t, 8> totp_counter(int period) {
  uint64_t t = static_cast<uint64_t>(std::time(nullptr)) / period;
  std::array<uint8_t, 8> result;
  for (int i = 0; i < 8; ++i) result[i] = (t >> (56 - i * 8)) & 0xFF;
  return result;
}

// See: TOTP: https://www.rfc-editor.org/rfc/rfc6238
// See: HOTP: https://www.rfc-editor.org/rfc/rfc4226
std::string TOTP::code() {
  auto now = totp_counter(period);
  std::vector<uint8_t> counter(now.begin(), now.end());
  
  std::vector<uint8_t> hash = hmac_totp(algorithm, secret, counter);

  int offset = hash[hash.size() - 1] & 0xF;
  uint64_t truncated = (
    ((hash[offset    ] & 0x7F) << 24) |
    ((hash[offset + 1] & 0xFF) << 16) |
    ((hash[offset + 2] & 0xFF) <<  8) |
    ((hash[offset + 3] & 0xFF)      )
  ) % ((int) pow(10, digits));

  std::string code = std::to_string(truncated);
  while (((int) code.size()) < digits) code = "0" + code;

  return code;
}

// See: https://github.com/google/google-authenticator/wiki/Key-Uri-Format
std::optional<TOTP> TOTP::from_url(const std::string& url) {
  TOTP totp;

  std::regex url_regex (
    R"(^otpauth://totp/([^:]+):([^?]+)\?(.*)$)",
    std::regex::extended
  );
  std::smatch url_match_result;

  if (std::regex_match(url, url_match_result, url_regex)) {
    totp.org = url_decode(url_match_result[1]);
    totp.account = url_decode(url_match_result[2]);

    std::string query = url_match_result[3];
    if (!query.empty()) {
      std::regex param_regex(R"(([^&=]+)=([^&]*))");
      auto params_begin = std::sregex_iterator(query.begin(), query.end(), param_regex);
      auto params_end = std::sregex_iterator();
      for (auto it = params_begin; it != params_end; ++it) {
        std::string key = url_decode((*it)[1]);
        std::string value = url_decode((*it)[2]);
        if (key == "secret")    totp.secret    = base32_decode(value);
        else if (key == "algorithm") totp.algorithm = value;
        else if (key == "digits")    totp.digits    = std::stoi(value);
        else if (key == "period")    totp.period    = std::stoi(value);
      }
    }
    if (totp.algorithm != "SHA1" && totp.algorithm != "SHA256" && totp.algorithm != "SHA512") {
      std::cerr << "Unknown algorithm: " << totp.algorithm << std::endl;
      return std::nullopt;
    }

  } else {
    std::cerr << "Malformed url." << std::endl;
    return std::nullopt;
  }

  return totp;
}
