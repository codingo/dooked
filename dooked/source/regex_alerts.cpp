#include "regex_alerts.hpp"
#include "utils/io_utils.hpp"
#include <fstream>
#include <regex>
#include <spdlog/spdlog.h>

namespace dooked {

namespace {
std::string dns_type_to_string(probe_result_t const &record) {
  return dns_record_type_to_str(record.type);
}

std::vector<std::string> values_for_field(
    std::string const &field, std::string const &domain,
    http_dns_response_t<probe_result_t> const &response) {
  std::vector<std::string> values{};
  if (field == "domain" || field == "name") {
    values.push_back(domain);
  } else if (field == "http_code") {
    values.push_back(std::to_string(response.http_result_.http_status_));
  } else if (field == "content_length") {
    values.push_back(std::to_string(response.http_result_.content_length_));
  } else if (field == "dns_type" || field == "type") {
    for (auto const &record : response.dns_result_list_) {
      values.push_back(dns_type_to_string(record));
    }
  } else if (field == "rdata" || field == "info") {
    for (auto const &record : response.dns_result_list_) {
      values.push_back(record.rdata);
    }
  }
  return values;
}
} // namespace

std::vector<regex_alert_rule_t>
load_regex_alert_rules(std::string const &filename) {
  if (filename.empty()) {
    return {};
  }

  std::ifstream file{filename};
  if (!file) {
    spdlog::error("Unable to open regex alert config `{}`", filename);
    return {};
  }

  try {
    auto const parsed = json::parse(file);
    auto const rule_list = parsed.contains("checks") ? parsed.at("checks") : parsed;
    std::vector<regex_alert_rule_t> rules{};
    for (auto const &rule_json : rule_list) {
      regex_alert_rule_t rule{};
      rule.field = rule_json.at("field").get<std::string>();
      rule.pattern = rule_json.at("regex").get<std::string>();
      rule.alert = rule_json.at("alert").get<std::string>();
      std::regex{rule.pattern};
      rules.push_back(std::move(rule));
    }
    return rules;
  } catch (std::exception const &e) {
    spdlog::error("Invalid regex alert config `{}`: {}", filename, e.what());
    return {};
  }
}

void run_regex_alerts(std::vector<regex_alert_rule_t> const &rules,
                      map_container_t<probe_result_t> const &result_map) {
  if (rules.empty()) {
    return;
  }

  std::vector<std::pair<regex_alert_rule_t, std::regex>> compiled_rules{};
  compiled_rules.reserve(rules.size());
  for (auto const &rule : rules) {
    compiled_rules.emplace_back(rule, std::regex{rule.pattern});
  }

  for (auto const &[domain, response] : result_map.cresult()) {
    for (auto const &[rule, matcher] : compiled_rules) {
      for (auto const &value : values_for_field(rule.field, domain, response)) {
        if (std::regex_search(value, matcher)) {
          spdlog::info("[REGEX ALERT][{}][{}] {} matched `{}`",
                       domain, rule.field, rule.alert, value);
        }
      }
    }
  }
}

} // namespace dooked
