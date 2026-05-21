#pragma once

#include "utils/containers.hpp"
#include "utils/probe_result.hpp"
#include <nlohmann/json.hpp>
#include <string>
#include <vector>

namespace dooked {

struct regex_alert_rule_t {
  std::string field{};
  std::string pattern{};
  std::string alert{};
};

std::vector<regex_alert_rule_t> load_regex_alert_rules(std::string const &filename);
void run_regex_alerts(std::vector<regex_alert_rule_t> const &rules,
                      map_container_t<probe_result_t> const &result_map);

} // namespace dooked
