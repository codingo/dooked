#pragma once

#include "utils/containers.hpp"
#include "utils/probe_result.hpp"
#include <iosfwd>
#include <optional>
#include <regex>
#include <string>
#include <vector>

namespace dooked {

enum class regex_check_field_e {
  domain,
  type,
  rdata,
  ttl,
  content_length,
  http_code,
  code_string,
  body
};

struct regex_check_t {
  regex_check_field_e field{};
  std::string field_name{};
  std::string pattern{};
  std::string alert{};
  bool ignore_case{};
  std::regex compiled_pattern{};
};

using regex_check_list_t = std::vector<regex_check_t>;

std::optional<regex_check_list_t>
parse_regex_checks_config(std::istream &input, std::string &error_message);

std::optional<regex_check_list_t>
load_regex_checks(std::string const &filename, std::string &error_message);

void run_regex_checks(map_container_t<probe_result_t> const &result_map,
                      regex_check_list_t const &checks);

} // namespace dooked
