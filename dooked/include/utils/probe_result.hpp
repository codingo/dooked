#pragma once

#include "utils/constants.hpp"
#include <string>

namespace dooked {

// defined in utils/string_utils.hpp
bool case_insensitive_compare(std::string const &, std::string const &);

struct probe_result_t {
  std::string rdata{};
  dns_record_type_e type{}; // RR TYPE (2 octets)
  std::uint32_t ttl{};      // time to live(4 octets)

  friend bool operator==(probe_result_t const &a, probe_result_t const &b) {
    return case_insensitive_compare(a.rdata, b.rdata) && (a.type == b.type);
  }
};

} // namespace dooked
