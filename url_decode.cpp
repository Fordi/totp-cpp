#include <string>
#include "url_decode.h"

std::string url_decode(const std::string& s) {
  std::string result;
  for (size_t i = 0; i < s.size(); ++i) {
    if (s[i] == '%' && i + 2 < s.size()) {
      int val = std::stoi(s.substr(i + 1, 2), nullptr, 16);
      result += static_cast<char>(val);
      i += 2;
    } else if (s[i] == '+') {
      result += ' ';
    } else {
      result += s[i];
    }
  }
  return result;
}
