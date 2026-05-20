#include "checks/regex_checks.hpp"
#include <cassert>
#include <regex>
#include <sstream>
#include <string>

int main() {
  using namespace dooked;

  std::string error;
  std::istringstream object_config{R"json(
    {
      "checks": [
        {
          "field": "domain_name",
          "regex": "(dev|test)",
          "alert": "environment marker",
          "ignore_case": true
        },
        {
          "field": "content",
          "pattern": "Copyright 2020",
          "message": "outdated copyright",
          "case_sensitive": true
        },
        {
          "field": "http_status",
          "regex": "^500$",
          "alert": "server error"
        },
        {
          "field": "info",
          "regex": "v=spf1",
          "alert": "SPF record"
        }
      ]
    }
  )json"};

  auto checks = parse_regex_checks_config(object_config, error);
  assert(checks);
  assert(error.empty());
  assert(checks->size() == 4);
  assert((*checks)[0].field == regex_check_field_e::domain);
  assert((*checks)[0].field_name == "domain");
  assert((*checks)[0].ignore_case);
  std::string test_domain{"TEST"};
  assert(std::regex_search(test_domain, (*checks)[0].compiled_pattern));
  assert((*checks)[1].field == regex_check_field_e::body);
  assert(!(*checks)[1].ignore_case);
  assert((*checks)[2].field == regex_check_field_e::http_code);
  assert((*checks)[3].field == regex_check_field_e::rdata);

  std::istringstream array_config{R"json([
    {"field": "ttl", "regex": "^300$", "alert": "ttl match"}
  ])json"};
  checks = parse_regex_checks_config(array_config, error);
  assert(checks);
  assert(checks->size() == 1);
  assert((*checks)[0].field == regex_check_field_e::ttl);

  std::istringstream invalid_field_config{R"json(
    {"checks": [{"field": "missing", "regex": "x", "alert": "bad"}]}
  )json"};
  checks = parse_regex_checks_config(invalid_field_config, error);
  assert(!checks);
  assert(error.find("unsupported field") != std::string::npos);

  std::istringstream invalid_regex_config{R"json(
    {"checks": [{"field": "domain", "regex": "(", "alert": "bad"}]}
  )json"};
  checks = parse_regex_checks_config(invalid_regex_config, error);
  assert(!checks);
  assert(error.find("invalid regex") != std::string::npos);

  std::istringstream conflicting_case_config{R"json(
    {
      "checks": [
        {
          "field": "domain",
          "regex": "dev",
          "alert": "bad flags",
          "ignore_case": true,
          "case_sensitive": true
        }
      ]
    }
  )json"};
  checks = parse_regex_checks_config(conflicting_case_config, error);
  assert(!checks);
  assert(error.find("conflicting") != std::string::npos);

  return 0;
}
