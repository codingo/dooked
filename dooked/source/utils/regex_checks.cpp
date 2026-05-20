#include "utils/regex_checks.hpp"
#include "utils/constants.hpp"
#include <cctype>
#include <fstream>
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

namespace dooked {
namespace {

using json = nlohmann::json;

std::string normalize_field(std::string const &field) {
  std::string normalized{};
  normalized.reserve(field.size());
  for (auto const ch : field) {
    if (ch == '_' || ch == '-') {
      continue;
    }
    normalized.push_back((char)std::tolower((unsigned char)ch));
  }
  return normalized;
}

bool is_domain_field(std::string const &field) {
  auto const key = normalize_field(field);
  return key == "domain" || key == "domainname" || key == "name";
}

bool is_dns_field(std::string const &field) {
  auto const key = normalize_field(field);
  return key == "type" || key == "dnstype" || key == "info" ||
         key == "rdata" || key == "ttl";
}

bool is_http_field(std::string const &field) {
  auto const key = normalize_field(field);
  return key == "httpcode" || key == "status" || key == "codestatus" ||
         key == "codestring" || key == "contentlength";
}

bool is_body_field(std::string const &field) {
  auto const key = normalize_field(field);
  return key == "body" || key == "content" || key == "page" ||
         key == "pagecontent" || key == "responsebody";
}

bool is_supported_field(std::string const &field) {
  return is_domain_field(field) || is_dns_field(field) ||
         is_http_field(field) || is_body_field(field);
}

std::optional<std::string> dns_value(std::string const &field,
                                     probe_result_t const &record) {
  auto const key = normalize_field(field);
  if (key == "type" || key == "dnstype") {
    return dns_record_type_to_str(record.type);
  }
  if (key == "info" || key == "rdata") {
    return record.rdata;
  }
  if (key == "ttl") {
    return std::to_string(record.ttl);
  }
  return std::nullopt;
}

std::optional<std::string> http_value(std::string const &field,
                                      int const http_code,
                                      int const content_length) {
  auto const key = normalize_field(field);
  if (key == "httpcode" || key == "status" || key == "codestatus") {
    return std::to_string(http_code);
  }
  if (key == "codestring") {
    return code_string(http_code);
  }
  if (key == "contentlength") {
    return std::to_string(content_length);
  }
  return std::nullopt;
}

void maybe_report(std::string const &domain_name, regex_check_t const &check,
                  std::string const &value) {
  if (std::regex_search(value, check.expression)) {
    spdlog::warn("[REGEX][{}][{}] {}", domain_name, check.field, check.alert);
  }
}

std::optional<regex_check_t> parse_check(json const &item,
                                         std::size_t const index) {
  if (!item.is_object()) {
    spdlog::error("regex check {} must be a JSON object", index);
    return std::nullopt;
  }
  if (!item.contains("field") || !item.contains("regex")) {
    spdlog::error("regex check {} must contain field and regex", index);
    return std::nullopt;
  }

  regex_check_t check{};
  check.field = item.at("field").get<std::string>();
  check.pattern = item.at("regex").get<std::string>();
  if (item.contains("alert")) {
    check.alert = item.at("alert").get<std::string>();
  } else if (item.contains("message")) {
    check.alert = item.at("message").get<std::string>();
  } else {
    check.alert = "matched configured check";
  }

  if (!is_supported_field(check.field)) {
    spdlog::error("regex check {} has unsupported field `{}`", index,
                  check.field);
    return std::nullopt;
  }

  auto flags = std::regex::ECMAScript;
  if (item.value("ignore_case", false) ||
      item.value("case_insensitive", false)) {
    flags |= std::regex::icase;
  }

  try {
    check.expression = std::regex(check.pattern, flags);
  } catch (std::regex_error const &e) {
    spdlog::error("regex check {} has invalid regex `{}`: {}", index,
                  check.pattern, e.what());
    return std::nullopt;
  }
  return check;
}

} // namespace

std::optional<regex_check_list_t>
load_regex_checks(std::string const &filename) {
  std::ifstream input_file(filename);
  if (!input_file) {
    spdlog::error("unable to open regex checks file `{}`", filename);
    return std::nullopt;
  }

  try {
    auto const root = json::parse(input_file);
    auto const checks_json =
        root.is_array() ? root : root.value("checks", json::array());
    if (!checks_json.is_array()) {
      spdlog::error("regex checks file must be an array or contain checks[]");
      return std::nullopt;
    }

    regex_check_list_t checks{};
    for (std::size_t index = 0; index < checks_json.size(); ++index) {
      auto check = parse_check(checks_json.at(index), index);
      if (!check) {
        return std::nullopt;
      }
      checks.push_back(std::move(*check));
    }
    return checks;
  } catch (std::exception const &e) {
    spdlog::error("unable to parse regex checks file `{}`: {}", filename,
                  e.what());
    return std::nullopt;
  }
}

void run_result_checks(regex_check_list_t const &checks,
                       map_container_t<probe_result_t> const &result_map) {
  if (checks.empty() || result_map.empty()) {
    return;
  }

  for (auto const &result_pair : result_map.cresult()) {
    auto const &domain_name = result_pair.first;
    auto const &domain_result = result_pair.second;
    auto const http_code = domain_result.http_result_.http_status_;
    auto const content_length = domain_result.http_result_.content_length_;

    for (auto const &check : checks) {
      if (is_body_field(check.field)) {
        continue;
      }
      if (is_domain_field(check.field)) {
        maybe_report(domain_name, check, domain_name);
        continue;
      }
      if (is_http_field(check.field)) {
        if (auto value = http_value(check.field, http_code, content_length)) {
          maybe_report(domain_name, check, *value);
        }
        continue;
      }
      for (auto const &record : domain_result.dns_result_list_) {
        if (auto value = dns_value(check.field, record)) {
          maybe_report(domain_name, check, *value);
        }
      }
    }
  }
}

void run_body_checks(regex_check_list_t const &checks,
                     std::string const &domain_name, int const,
                     int const, std::string const &body) {
  if (checks.empty() || body.empty()) {
    return;
  }
  for (auto const &check : checks) {
    if (is_body_field(check.field)) {
      maybe_report(domain_name, check, body);
    }
  }
}

} // namespace dooked
