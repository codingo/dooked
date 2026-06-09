#pragma once

#include "utils/constants.hpp"
#include <chrono>
#include <cstdint>
#include <string>

namespace dooked {

// defined in utils/string_utils.hpp
bool case_insensitive_compare(std::string const &, std::string const &);

struct probe_result_t {
  std::string rdata{};
  dns_record_type_e type{}; // RR TYPE (2 octets)
  std::uint32_t ttl{};      // time to live(4 octets)
  std::uint64_t first_seen{}; // epoch seconds, set on first observation
  std::uint64_t last_seen{};  // epoch seconds, updated on every observation
  std::uint32_t seen_count{}; // number of times this record was observed

  static std::uint64_t now_epoch() {
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch())
            .count());
  }

  friend bool operator==(probe_result_t const &a, probe_result_t const &b) {
    return case_insensitive_compare(a.rdata, b.rdata) && (a.type == b.type);
  }
};

} // namespace dooked
