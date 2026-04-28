#include <emscripten/bind.h>
#include <stdexcept>
#include "TOTP.h"

using namespace emscripten;

static TOTP from_url_or_throw(const std::string& url) {
  auto result = TOTP::from_url(url);
  if (!result) throw std::runtime_error("Malformed URL");
  return *result;
}

EMSCRIPTEN_BINDINGS(totp) {
  class_<TOTP>("TOTP")
    .class_function("from_url", &from_url_or_throw)
    .function("code", &TOTP::code)
    .property("label",     &TOTP::label)
    .property("account",   &TOTP::account)
    .property("issuer",    &TOTP::issuer)
    .property("algorithm", &TOTP::algorithm)
    .property("digits",    &TOTP::digits)
    .property("period",    &TOTP::period)
    ;
}
