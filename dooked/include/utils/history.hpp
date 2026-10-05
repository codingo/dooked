#pragma once

#include <nlohmann/json.hpp>
#include <algorithm>
#include <cctype>
#include <cstdint>
#include <limits>
#include <map>
#include <set>
#include <stdexcept>
#include <string>
#include <tuple>

namespace dooked {
using history_json = nlohmann::json;

inline std::string history_domain(std::string name) {
  std::transform(name.begin(), name.end(), name.begin(), [](unsigned char c) {
    return static_cast<char>(std::tolower(c));
  });
  return name;
}

inline std::int64_t history_number(history_json const &record,
                                   char const *field) {
  auto it = record.find(field);
  if (it == record.end() || it->is_null()) return 0;
  if (!it->is_number_integer() || *it < 0 ||
      *it > std::numeric_limits<std::int64_t>::max()) {
    throw std::runtime_error(std::string("invalid history field: ") + field);
  }
  return it->get<std::int64_t>();
}

// UTC midnight, without local timezone/DST or permissive date normalization.
inline std::int64_t history_us_date(std::string const &text) {
  if (text.size() != 10 || text[2] != '/' || text[5] != '/')
    throw std::invalid_argument("--lsd requires MM/DD/YYYY");
  for (std::size_t i = 0; i < text.size(); ++i)
    if (i != 2 && i != 5 && !std::isdigit(static_cast<unsigned char>(text[i])))
      throw std::invalid_argument("--lsd requires MM/DD/YYYY");
  int month = std::stoi(text.substr(0, 2));
  int day = std::stoi(text.substr(3, 2));
  int year = std::stoi(text.substr(6, 4));
  bool leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
  int const lengths[] = {31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
  if (year < 1970 || month < 1 || month > 12 || day < 1 || day > lengths[month - 1])
    throw std::invalid_argument("--lsd requires a valid date on or after 01/01/1970");
  std::int64_t days = 0;
  for (int y = 1970; y < year; ++y)
    days += y % 4 == 0 && (y % 100 != 0 || y % 400 == 0) ? 366 : 365;
  for (int m = 1; m < month; ++m) days += lengths[m - 1];
  return (days + day - 1) * 86400;
}

inline history_json merge_dns_history(history_json current,
                                       history_json const &previous,
                                       std::int64_t now) {
  if (now <= 0) throw std::invalid_argument("scan timestamp must be positive");
  using key_t = std::tuple<std::string, std::string, std::string>;
  std::map<key_t, history_json> records;
  std::map<std::string, history_json> domains;
  auto ingest = [&](history_json const &snapshot, bool observed) {
    std::set<key_t> scanned;
    for (auto const &entry : snapshot.at("result")) {
      for (auto it = entry.begin(); it != entry.end(); ++it) {
        auto domain = history_domain(it.key());
        // New HTTP fields override previous values; historical-only domains survive.
        domains[domain] = it.value();
        for (auto record : it.value().at("dns_probe")) {
          key_t key{domain, record.at("type").get<std::string>(),
                    record.at("info").get<std::string>()};
          if (!scanned.insert(key).second) continue;
          auto first = history_number(record, "first-seen");
          auto last = history_number(record, "last-seen");
          auto seen = history_number(record, "seen");
          if (first && last && first > last)
            throw std::runtime_error("first-seen exceeds last-seen");
          bool newly_observed = false;
          if (observed) {
            auto old = records.find(key);
            newly_observed = old == records.end();
            if (old != records.end()) {
              first = history_number(old->second, "first-seen");
              last = history_number(old->second, "last-seen");
              seen = history_number(old->second, "seen");
            }
            if (!first) first = now;
            last = std::max(last, now);
            if (seen == std::numeric_limits<std::int64_t>::max())
              throw std::runtime_error("seen counter overflow");
            ++seen;
          }
          record["first-seen"] = first ? history_json(first) : history_json(nullptr);
          record["last-seen"] = last ? history_json(last) : history_json(nullptr);
          record["seen"] = seen;
          record["observed"] = observed;
          record["newly-observed"] = newly_observed;
          records[key] = std::move(record);
        }
      }
    }
  };
  ingest(previous, false);
  ingest(current, true);
  for (auto &domain : domains) domain.second["dns_probe"] = history_json::array();
  for (auto const &record : records)
    domains[std::get<0>(record.first)]["dns_probe"].push_back(record.second);
  current["result"] = history_json::array();
  for (auto const &domain : domains)
    current["result"].push_back(history_json{{domain.first, domain.second}});
  current["scan-time"] = now;
  return current;
}

inline bool history_missing(history_json const &record, std::int64_t now,
                             std::int64_t days, std::int64_t date) {
  if (record.at("observed").get<bool>()) return false;
  auto last = history_number(record, "last-seen");
  if (days >= 0 && (days == 0 || (last && last <= now && days <= (now - last) / 86400)))
    return true;
  return date >= 0 && last && last < date;
}
} // namespace dooked
