#pragma once

#include <stdexcept>

namespace dooked {

struct empty_container_exception_t : std::runtime_error {
  empty_container_exception_t() : std::runtime_error{"empty container"} {}
};

struct invalid_dns_response_t : std::runtime_error {
  invalid_dns_response_t() : std::runtime_error{"invalid dns response"} {}
  invalid_dns_response_t(char const *w) : std::runtime_error{w} {}
};

struct general_exception_t : std::runtime_error {
  general_exception_t(char const *w) : std::runtime_error{w} {}
  general_exception_t(std::string const &w) : std::runtime_error{w.c_str()} {}
};

struct bad_name_exception_t : std::runtime_error {
  bad_name_exception_t(std::string const &domain_name)
      : std::runtime_error{domain_name} {}
  bad_name_exception_t(char const *name) : std::runtime_error{name} {}
};

} // namespace dooked
