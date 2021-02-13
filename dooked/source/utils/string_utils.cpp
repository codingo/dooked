#include "utils/string_utils.hpp"
#include <algorithm>
#include <ctime>
#include <sstream>

namespace dooked {
void ltrim(std::string &s) {
  s.erase(s.begin(), std::find_if(s.begin(), s.end(), [](unsigned char ch) {
            return !std::isspace(ch);
          }));
}

void rtrim(std::string &s) {
  s.erase(std::find_if(s.rbegin(), s.rend(),
                       [](unsigned char ch) { return !std::isspace(ch); })
              .base(),
          s.end());
}

void trim(std::string &s) {
  ltrim(s);
  rtrim(s);
}

std::string ltrim_copy(std::string s) {
  ltrim(s);
  return s;
}

std::string rtrim_copy(std::string s) {
  rtrim(s);
  return s;
}

std::string trim_copy(std::string s) {
  trim(s);
  return s;
}

void trim_string(std::string &str) { trim(str); }

bool starts_with(std::string const &str, std::string const &prefix) {
  return str.size() >= prefix.size() &&
         std::equal(str.cbegin(), str.cbegin() + prefix.size(), prefix.cbegin(),
                    [](char const a, char const b) {
                      return (std::toupper(a) == std::toupper(b));
                    });
}

bool case_insensitive_compare(std::string const &a, std::string const &b) {
  return (a.size() == b.size()) &&
         std::equal(a.cbegin(), a.cend(), b.cbegin(),
                    [](char const a, char const b) {
                      return (std::toupper(a) == std::toupper(b));
                    });
}

void split_string(std::string const &str, std::vector<std::string> &cont,
                  char const delim) {
  std::stringstream ss{str};
  std::string token{};
  while (std::getline(ss, token, delim)) {
    trim(token);
    if (!token.empty()) {
      cont.push_back(token);
    }
  }
}

uri_t::uri_t(std::string const &url_s) { parse(url_s); }

std::string uri_t::host() const { return host_; }

void uri_t::parse(std::string const &url_s) {
  std::string const prot_end{"://"};
  std::string::const_iterator prot_iter = std::search(
      url_s.cbegin(), url_s.cend(), prot_end.cbegin(), prot_end.cend());
  if (prot_iter == url_s.end()) {
    prot_iter = url_s.cbegin();
  } else {
    std::advance(prot_iter, prot_end.length());
  }
  std::string::const_iterator path_i = std::find(prot_iter, url_s.end(), '/');
  host_.reserve(static_cast<std::size_t>(std::distance(prot_iter, path_i)));
  std::transform(prot_iter, path_i, std::back_inserter(host_),
                 [](int c) { return std::tolower(c); });
}

bool timet_to_string(std::string &output, std::size_t t, char const *format) {
  std::time_t current_time = t;
#if _MSC_VER && !__INTEL_COMPILER
#pragma warning(disable : 4996)
#endif
  auto const tm_t = std::localtime(&current_time);

  if (!tm_t) {
    return false;
  }
  output.clear();
  output.resize(32);
  auto const trimmed_size =
      std::strftime(output.data(), output.size(), format, tm_t);
  if (trimmed_size > 0) {
    output.resize(trimmed_size);
    return true;
  }
  output.clear();
  return false;
}

} // namespace dooked
