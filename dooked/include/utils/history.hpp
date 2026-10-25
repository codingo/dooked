#pragma once

#include <nlohmann/json.hpp>
#include <algorithm>
#include <cctype>
#include <cstdint>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace dooked {
namespace history {
using json = nlohmann::json;
inline std::string key(std::string value) {
  std::transform(value.begin(), value.end(), value.begin(),
                 [](unsigned char c) { return std::tolower(c); });
  return value;
}
inline std::string timestamp(std::time_t now) {
  auto tm = *std::gmtime(&now);
  std::ostringstream out;
  out << std::put_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
  return out.str();
}
// Validate calendar dates, rather than silently normalizing e.g. February 30.
inline std::string cutoff_date(std::string const &date) {
  std::tm tm{};
  std::istringstream in(date);
  in >> std::get_time(&tm, "%m/%d/%Y");
  if (in.fail() || in.peek() != std::char_traits<char>::eof())
    throw std::invalid_argument("--lsd expects MM/DD/YYYY");
  int year = tm.tm_year + 1900, month = tm.tm_mon + 1, day = tm.tm_mday;
  int days[] = {31,28,31,30,31,30,31,31,30,31,30,31};
  if (year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)) days[1] = 29;
  if (year < 1900 || month < 1 || month > 12 || day < 1 || day > days[month-1])
    throw std::invalid_argument("--lsd expects a valid calendar date");
  std::ostringstream out;
  out << std::put_time(&tm, "%Y-%m-%dT00:00:00Z");
  return out.str();
}
struct event_t {
  std::string domain;
  json record;
  bool fresh;
};
// Input/output is the existing result array. Only observations in current
// advance last-seen and seen; retained records never become observations.
inline std::vector<event_t> merge(json::array_t &current,
                                 json::array_t const &previous,
                                 std::string const &now) {
  auto identity = [](json const &r) {
    return key(r.at("type").get<std::string>()) + ":" +
           key(r.at("info").get<std::string>());
  };
  json old = json::object(), domains = json::object();
  for (auto const &item : previous)
    for (auto it = item.begin(); it != item.end(); ++it) {
      auto d = key(it.key());
      domains[d] = it.value();
      for (auto const &record : it.value().at("dns_probe"))
        old[d][identity(record)] = record;
    }
  std::vector<event_t> events;
  for (auto &item : current)
    for (auto it = item.begin(); it != item.end(); ++it) {
      auto d = key(it.key());
      for (auto &record : it.value()["dns_probe"]) {
        auto id = identity(record);
        bool fresh = !old.contains(d) || !old[d].contains(id);
        json prior = fresh ? json::object() : old[d][id];
        record["first-seen"] = prior.value("first-seen", now);
        record["last-seen"] = now;
        record["seen"] = prior.value("seen", std::uint64_t{0}) + 1;
        if (fresh) events.push_back({it.key(), record, true});
        if (!fresh) old[d].erase(id);
      }
    }
  for (auto dit = old.begin(); dit != old.end(); ++dit) {
    if (dit.value().empty()) continue;
    json *details = nullptr;
    for (auto &item : current)
      for (auto it = item.begin(); it != item.end(); ++it)
        if (key(it.key()) == dit.key()) details = &it.value();
    if (!details) {
      json domain = domains[dit.key()];
      domain["dns_probe"] = json::array();
      current.push_back(json{{dit.key(), domain}});
      details = &current.back()[dit.key()];
    }
    for (auto const &record : dit.value()) {
      // A legacy absent record has no known observation date. Preserve it
      // without inventing a date; date alerts begin once it is observed.
      (*details)["dns_probe"].push_back(record);
      events.push_back({dit.key(), record, false});
    }
  }
  return events;
}
} // namespace history
} // namespace dooked
