#include <iostream>

#include "../TOTP.h"

#define TOTP_DEBUG

int main(int argc, char *argv[]) {
  std::string url(argv[1]);
  auto totp = TOTP::from_url(url);
  if (!totp) {
    return 1;
  }
  #ifdef TOTP_DEBUG
  std::cerr << "label:     " << totp->label         << std::endl;
  std::cerr << "account:   " << totp->account       << std::endl;
  std::cerr << "secret:    " << totp->secret.size() << " bytes" << std::endl;
  std::cerr << "algorithm: " << totp->algorithm     << std::endl;
  std::cerr << "digits:    " << totp->digits        << std::endl;
  std::cerr << "period:    " << totp->period        << std::endl;
  std::cerr << "issuer:    " << totp->issuer        << std::endl;
  std::cerr << "code:      ";
  #endif
  std::cout << totp->code() << std::endl;
  return 0;
}