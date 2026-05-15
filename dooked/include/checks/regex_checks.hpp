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
  std::regex compiled_pattern{};
  bool body_field{false};
};

using regex_check_list_t = std::vector<regex_check_t>;

std::optional<regex_check_list_t>
load_regex_checks(std::string const &filename, std::string &error_message);

void run_regex_checks(map_container_t<probe_result_t> const &result_map,
                      regex_check_list_t const &checks);

} // namespace dooked
