#include "checks/regex_checks.hpp"
#include "utils/constants.hpp"
#include <algorithm>
#include <cctype>
#include <fstream>
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>
#include <sstream>

namespace dooked {
namespace {

using json = nlohmann::json;

std::string lowercase(std::string value) {
  std::transform(value.begin(), value.end(), value.begin(), [](char ch) {
    return static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
  });
  return value;
}

std::optional<std::string> canonical_field(std::string field) {
  field = lowercase(std::move(field));
  std::replace(field.begin(), field.end(), '-', '_');

  if (field == "domain" || field == "domain_name" || field == "name") {
    return "domain";
  }
  if (field == "type" || field == "record_type") {
    return "type";
  }
  if (field == "info" || field == "rdata" || field == "data") {
    return "rdata";
  }
  if (field == "ttl") {
    return "ttl";
  }
  if (field == "http_code" || field == "status" || field == "status_code") {
    return "http_code";
  }
  if (field == "code_string" || field == "status_text") {
    return "code_string";
  }
  if (field == "content_length") {
    return "content_length";
  }
  if (field == "body" || field == "content" || field == "page_content" ||
      field == "response_body" || field == "http_body") {
    return "body";
  }
  return std::nullopt;
}

bool is_body_field(std::string const &field) { return field == "body"; }

std::optional<std::string> json_string_value(json const &object,
                                             char const *key) {
  auto const iter = object.find(key);
  if (iter == object.end() || !iter->is_string()) {
    return std::nullopt;
  }
  return iter->get<std::string>();
}

std::string preview_value(std::string value) {
  constexpr std::size_t max_preview_size = 120;
  std::replace(value.begin(), value.end(), '\n', ' ');
  std::replace(value.begin(), value.end(), '\r', ' ');
  if (value.size() > max_preview_size) {
    value.resize(max_preview_size);
    value += "...";
  }
  return value;
}

void report_match(regex_check_t const &check, std::string const &domain,
                  std::string const &value) {
  if (value.empty()) {
    return;
  }

  std::smatch match;
  if (!std::regex_search(value, match, check.compiled_pattern)) {
    return;
  }

  auto matched = match.empty() ? value : match.str(0);
  spdlog::warn("[REGEX][{}][{}] {} (matched: `{}`)", check.field, domain,
               check.alert, preview_value(std::move(matched)));
}

std::string http_field_value(http_response_t const &response,
                             std::string const &field) {
  if (field == "http_code") {
    return std::to_string(response.http_status_);
  }
  if (field == "code_string") {
    return code_string(response.http_status_);
  }
  if (field == "content_length") {
    return std::to_string(response.content_length_);
  }
  if (field == "body") {
    return response.body_;
  }
  return {};
}

std::string dns_field_value(probe_result_t const &record,
                            std::string const &field) {
  if (field == "type") {
    return dns_record_type_to_str(record.type);
  }
  if (field == "rdata") {
    return record.rdata;
  }
  if (field == "ttl") {
    return std::to_string(record.ttl);
  }
  return {};
}

} // namespace

std::optional<regex_check_list_t>
load_regex_checks(std::string const &filename, std::string &error_message) {
  std::ifstream input_file(filename);
  if (!input_file) {
    error_message = "unable to open check config: " + filename;
    return std::nullopt;
  }

  json parsed;
  try {
    input_file >> parsed;
  } catch (std::exception const &e) {
    error_message = "invalid JSON check config: " + std::string(e.what());
    return std::nullopt;
  }

  json checks_json;
  if (parsed.is_array()) {
    checks_json = parsed;
  } else if (parsed.is_object() && parsed.contains("checks") &&
             parsed["checks"].is_array()) {
    checks_json = parsed["checks"];
  } else {
    error_message = "check config must be an array or an object with a checks "
                    "array";
    return std::nullopt;
  }

  regex_check_list_t checks;
  std::size_t index = 0;
  for (auto const &check_json : checks_json) {
    ++index;
    if (!check_json.is_object()) {
      error_message = "check #" + std::to_string(index) + " must be an object";
      return std::nullopt;
    }

    auto raw_field = json_string_value(check_json, "field");
    auto raw_pattern = json_string_value(check_json, "regex");
    if (!raw_pattern) {
      raw_pattern = json_string_value(check_json, "pattern");
    }
    auto raw_alert = json_string_value(check_json, "alert");
    if (!raw_alert) {
      raw_alert = json_string_value(check_json, "message");
    }

    if (!raw_field || raw_field->empty()) {
      error_message = "check #" + std::to_string(index) +
                      " is missing a field value";
      return std::nullopt;
    }
    if (!raw_pattern || raw_pattern->empty()) {
      error_message = "check #" + std::to_string(index) +
                      " is missing a regex value";
      return std::nullopt;
    }
    if (!raw_alert || raw_alert->empty()) {
      error_message = "check #" + std::to_string(index) +
                      " is missing an alert value";
      return std::nullopt;
    }

    auto field = canonical_field(*raw_field);
    if (!field) {
      error_message = "check #" + std::to_string(index) +
                      " uses an unsupported field: " + *raw_field;
      return std::nullopt;
    }

    bool ignore_case = check_json.value("ignore_case", false);
    if (check_json.contains("case_sensitive") &&
        check_json["case_sensitive"].is_boolean()) {
      ignore_case = !check_json["case_sensitive"].get<bool>();
    }

    auto flags = std::regex_constants::ECMAScript;
    if (ignore_case) {
      flags |= std::regex_constants::icase;
    }

    try {
      checks.push_back({*field, *raw_pattern, *raw_alert,
                        std::regex(*raw_pattern, flags),
                        is_body_field(*field)});
    } catch (std::regex_error const &e) {
      error_message = "check #" + std::to_string(index) +
                      " has an invalid regex: " + e.what();
      return std::nullopt;
    }
  }

  if (checks.empty()) {
    error_message = "check config does not contain any checks";
    return std::nullopt;
  }
  return checks;
}

void run_regex_checks(map_container_t<probe_result_t> const &result_map,
                      regex_check_list_t const &checks) {
  for (auto const &result_pair : result_map.cresult()) {
    auto const &domain = result_pair.first;
    auto const &response = result_pair.second;

    for (auto const &check : checks) {
      if (check.field == "domain") {
        report_match(check, domain, domain);
      } else if (check.field == "http_code" || check.field == "code_string" ||
                 check.field == "content_length" || check.field == "body") {
        report_match(check, domain,
                     http_field_value(response.http_result_, check.field));
      }
    }

    for (auto const &record : response.dns_result_list_) {
      for (auto const &check : checks) {
        if (check.field == "type" || check.field == "rdata" ||
            check.field == "ttl") {
          report_match(check, domain, dns_field_value(record, check.field));
        }
      }
    }
  }
}

} // namespace dooked
