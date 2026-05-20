#include "checks/regex_checks.hpp"
#include "utils/io_utils.hpp"
#include <algorithm>
#include <cctype>
#include <fstream>
#include <spdlog/spdlog.h>
#include <utility>

namespace dooked {
namespace {

std::string normalize_field_name(std::string field) {
  std::transform(field.begin(), field.end(), field.begin(),
                 [](unsigned char c) {
                   if (c == '-') {
                     return '_';
                   }
                   return static_cast<char>(std::tolower(c));
                 });
  return field;
}

std::optional<regex_check_field_e>
field_from_name(std::string const &field_name) {
  if (field_name == "domain" || field_name == "domain_name") {
    return regex_check_field_e::domain;
  }
  if (field_name == "type") {
    return regex_check_field_e::type;
  }
  if (field_name == "info" || field_name == "rdata") {
    return regex_check_field_e::rdata;
  }
  if (field_name == "ttl") {
    return regex_check_field_e::ttl;
  }
  if (field_name == "content_length") {
    return regex_check_field_e::content_length;
  }
  if (field_name == "http_code" || field_name == "http_status") {
    return regex_check_field_e::http_code;
  }
  if (field_name == "code_string") {
    return regex_check_field_e::code_string;
  }
  if (field_name == "body" || field_name == "content" ||
      field_name == "page_content" || field_name == "response_body" ||
      field_name == "http_body") {
    return regex_check_field_e::body;
  }
  return std::nullopt;
}

std::string canonical_field_name(regex_check_field_e const field) {
  switch (field) {
  case regex_check_field_e::domain:
    return "domain";
  case regex_check_field_e::type:
    return "type";
  case regex_check_field_e::rdata:
    return "rdata";
  case regex_check_field_e::ttl:
    return "ttl";
  case regex_check_field_e::content_length:
    return "content_length";
  case regex_check_field_e::http_code:
    return "http_code";
  case regex_check_field_e::code_string:
    return "code_string";
  case regex_check_field_e::body:
    return "body";
  }
  return {};
}

std::string supported_field_names() {
  return "domain/domain_name, type, info/rdata, ttl, content_length, "
         "http_code/http_status, code_string, body/response_body/content";
}

std::optional<std::string> json_string(json const &object,
                                       char const *field_name) {
  auto const iter = object.find(field_name);
  if (iter == object.end() || !iter->is_string()) {
    return std::nullopt;
  }
  return iter->get<std::string>();
}

std::optional<bool> json_bool(json const &object, char const *field_name,
                              std::string &error_message,
                              std::size_t const index) {
  auto const iter = object.find(field_name);
  if (iter == object.end()) {
    return std::nullopt;
  }
  if (!iter->is_boolean()) {
    error_message = "check #" + std::to_string(index) + " has a non-boolean `" +
                    field_name + "` value";
    return std::nullopt;
  }
  return iter->get<bool>();
}

std::optional<bool> parse_ignore_case(json const &check_json,
                                      std::string &error_message,
                                      std::size_t const index) {
  auto const ignore_case =
      json_bool(check_json, "ignore_case", error_message, index);
  if (!error_message.empty()) {
    return std::nullopt;
  }

  auto const case_sensitive =
      json_bool(check_json, "case_sensitive", error_message, index);
  if (!error_message.empty()) {
    return std::nullopt;
  }

  if (ignore_case && case_sensitive && (*ignore_case == *case_sensitive)) {
    error_message = "check #" + std::to_string(index) +
                    " has conflicting `ignore_case` and `case_sensitive` "
                    "values";
    return std::nullopt;
  }

  if (case_sensitive) {
    return !*case_sensitive;
  }
  return ignore_case.value_or(false);
}

bool is_domain_or_http_field(regex_check_field_e const field) {
  return field == regex_check_field_e::domain ||
         field == regex_check_field_e::content_length ||
         field == regex_check_field_e::http_code ||
         field == regex_check_field_e::code_string ||
         field == regex_check_field_e::body;
}

bool is_dns_record_field(regex_check_field_e const field) {
  return field == regex_check_field_e::type ||
         field == regex_check_field_e::rdata ||
         field == regex_check_field_e::ttl;
}

std::string http_field_value(http_response_t const &response,
                             regex_check_field_e const field) {
  switch (field) {
  case regex_check_field_e::content_length:
    return std::to_string(response.content_length_);
  case regex_check_field_e::http_code:
    return std::to_string(response.http_status_);
  case regex_check_field_e::code_string:
    return code_string(response.http_status_);
  case regex_check_field_e::body:
    return response.body_;
  default:
    return {};
  }
}

std::string dns_field_value(probe_result_t const &record,
                            regex_check_field_e const field) {
  switch (field) {
  case regex_check_field_e::type:
    return dns_record_type_to_str(record.type);
  case regex_check_field_e::rdata:
    return record.rdata;
  case regex_check_field_e::ttl:
    return std::to_string(record.ttl);
  default:
    return {};
  }
}

std::string preview_match(std::string value) {
  constexpr std::size_t max_preview_size = 160;
  for (auto &c : value) {
    auto const uc = static_cast<unsigned char>(c);
    if (c == '\n' || c == '\r' || c == '\t' || std::iscntrl(uc)) {
      c = ' ';
    }
  }
  if (value.size() > max_preview_size) {
    value.resize(max_preview_size);
    value += "...";
  }
  return value;
}

void report_match(std::string const &domain_name, regex_check_t const &check,
                  std::string const &value) {
  std::smatch match;
  if (!std::regex_search(value, match, check.compiled_pattern)) {
    return;
  }

  auto matched_value = match.empty() ? value : match.str(0);
  spdlog::warn("[REGEX][{}][{}] {} (matched: `{}`)", domain_name,
               check.field_name, check.alert,
               preview_match(std::move(matched_value)));
}

void report_match(std::string const &domain_name, regex_check_t const &check,
                  probe_result_t const &record, std::string const &value) {
  std::smatch match;
  if (!std::regex_search(value, match, check.compiled_pattern)) {
    return;
  }

  auto matched_value = match.empty() ? value : match.str(0);
  spdlog::warn("[REGEX][{}][{}][{}] {} (matched: `{}`)", domain_name,
               check.field_name, dns_record_type_to_str(record.type),
               check.alert, preview_match(std::move(matched_value)));
}

} // namespace

std::optional<regex_check_list_t>
parse_regex_checks_config(std::istream &input, std::string &error_message) {
  error_message.clear();

  json root;
  try {
    root = json::parse(input);
  } catch (json::exception const &e) {
    error_message = "invalid JSON check config: " + std::string(e.what());
    return std::nullopt;
  }

  json const *checks_json = nullptr;
  if (root.is_array()) {
    checks_json = &root;
  } else if (root.is_object()) {
    auto const iter = root.find("checks");
    if (iter != root.end() && iter->is_array()) {
      checks_json = &(*iter);
    }
  }

  if (!checks_json) {
    error_message =
        "check config must be a JSON array or an object with a `checks` array";
    return std::nullopt;
  }

  regex_check_list_t checks;
  checks.reserve(checks_json->size());

  std::size_t index = 0;
  for (auto const &check_json : *checks_json) {
    ++index;
    if (!check_json.is_object()) {
      error_message = "check #" + std::to_string(index) + " must be an object";
      return std::nullopt;
    }

    auto raw_field = json_string(check_json, "field");
    if (!raw_field || raw_field->empty()) {
      error_message =
          "check #" + std::to_string(index) + " is missing a string `field`";
      return std::nullopt;
    }

    auto raw_pattern = json_string(check_json, "regex");
    if (!raw_pattern) {
      raw_pattern = json_string(check_json, "pattern");
    }
    if (!raw_pattern || raw_pattern->empty()) {
      error_message =
          "check #" + std::to_string(index) + " is missing a string `regex`";
      return std::nullopt;
    }

    auto raw_alert = json_string(check_json, "alert");
    if (!raw_alert) {
      raw_alert = json_string(check_json, "message");
    }
    if (!raw_alert || raw_alert->empty()) {
      error_message =
          "check #" + std::to_string(index) + " is missing a string `alert`";
      return std::nullopt;
    }

    auto const normalized_field = normalize_field_name(*raw_field);
    auto const field = field_from_name(normalized_field);
    if (!field) {
      error_message = "check #" + std::to_string(index) +
                      " uses unsupported field `" + *raw_field +
                      "`; supported fields: " + supported_field_names();
      return std::nullopt;
    }

    auto const ignore_case =
        parse_ignore_case(check_json, error_message, index);
    if (!ignore_case) {
      return std::nullopt;
    }

    auto flags = std::regex_constants::ECMAScript;
    if (*ignore_case) {
      flags |= std::regex_constants::icase;
    }

    try {
      checks.push_back({*field, canonical_field_name(*field), *raw_pattern,
                        *raw_alert, *ignore_case,
                        std::regex(*raw_pattern, flags)});
    } catch (std::regex_error const &e) {
      error_message = "check #" + std::to_string(index) +
                      " has invalid regex `" + *raw_pattern +
                      "`: " + e.what();
      return std::nullopt;
    }
  }

  if (checks.empty()) {
    error_message = "check config does not contain any checks";
    return std::nullopt;
  }

  return checks;
}

std::optional<regex_check_list_t>
load_regex_checks(std::string const &filename, std::string &error_message) {
  error_message.clear();

  std::ifstream file{filename};
  if (!file) {
    error_message = "unable to open check config `" + filename + "`";
    return std::nullopt;
  }

  auto checks = parse_regex_checks_config(file, error_message);
  if (!checks && !error_message.empty()) {
    error_message += " in `" + filename + "`";
  }
  return checks;
}

void run_regex_checks(map_container_t<probe_result_t> const &result_map,
                      regex_check_list_t const &checks) {
  if (checks.empty() || result_map.empty()) {
    return;
  }

  for (auto const &result_pair : result_map.cresult()) {
    auto const &domain_name = result_pair.first;
    auto const &domain_result = result_pair.second;

    for (auto const &check : checks) {
      if (!is_domain_or_http_field(check.field)) {
        continue;
      }

      if (check.field == regex_check_field_e::domain) {
        report_match(domain_name, check, domain_name);
      } else {
        report_match(domain_name, check,
                     http_field_value(domain_result.http_result_, check.field));
      }
    }

    for (auto const &record : domain_result.dns_result_list_) {
      for (auto const &check : checks) {
        if (!is_dns_record_field(check.field)) {
          continue;
        }

        report_match(domain_name, check, record,
                     dns_field_value(record, check.field));
      }
    }
  }
}

} // namespace dooked
