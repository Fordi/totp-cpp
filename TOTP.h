#ifndef TOTP_H
#define TOTP_H

#include <array>
#include <cstdint>
#include <string>
#include <vector>
#include <optional>

using namespace std;

class TOTP {
  public:
    int period = 30;
    int digits = 6;
    vector<uint8_t> secret;
    string algorithm = "SHA1";
    string label;
    string account;
    string issuer;
    string code();
    static optional<TOTP> from_url(const string& url);
};

#endif