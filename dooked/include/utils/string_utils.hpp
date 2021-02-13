#pragma once
#include <string>
#include <vector>

namespace dooked {

struct uri_t {
  uri_t(std::string const &url_s);
  std::string host() const;

private:
  void parse(std::string const &);
  std::string host_{};
};

bool starts_with(std::string const &str, std::string const &prefix);
void split_string(std::string const &str, std::vector<std::string> &cont,
                  char const delim);
bool timet_to_string(std::string &output, std::size_t t, char const *format);
void trim(std::string &s);
std::string trim_copy(std::string s);
void trim_string(std::string &);

} // namespace dooked
