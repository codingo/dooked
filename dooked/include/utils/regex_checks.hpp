#pragma once

#include "utils/containers.hpp"
#include "utils/probe_result.hpp"
#include <optional>
#include <regex>
#include <string>
#include <vector>

namespace dooked {

struct regex_check_t {
  std::string field{};
  std::string pattern{};
  std::string alert{};
  std::regex expression{};
};

using regex_check_list_t = std::vector<regex_check_t>;

std::optional<regex_check_list_t>
load_regex_checks(std::string const &filename);

void run_result_checks(regex_check_list_t const &checks,
                       map_container_t<probe_result_t> const &result_map);

void run_body_checks(regex_check_list_t const &checks,
                     std::string const &domain_name, int const http_code,
                     int const content_length, std::string const &body);

} // namespace dooked
