#pragma once

#include "utils/containers.hpp"
#include "utils/probe_result.hpp"
#include <algorithm>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <nlohmann/json.hpp>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <utility>

namespace dooked {

using json = nlohmann::json;
template <typename T> using opt_list_t = std::optional<std::vector<T>>;

void to_json(json &j, probe_result_t const &record);
dns_record_type_e dns_str_to_record_type(std::string const &);
bool is_text_file(std::string const &file_extension);
bool is_json_file(std::string const &file_extension);
std::string get_file_type(std::filesystem::path const &file_path);
std::string get_filepath(std::string const &filename);
std::uint16_t uint16_value(unsigned char const *buff);
void trim(std::string &);

struct json_data_t {
  std::string domain_name{};
  std::string rdata{};
  int ttl{};
  int http_code{};
  int content_length{};
  dns_record_type_e type{};
  std::string first_seen{};
  std::string last_seen{};
  int seen{};

  static json_data_t serialize(std::string const &d, int const len,
                               int const http_code,
                               json::object_t &json_object) {
    json_data_t data{};
    data.domain_name = d;
    data.type =
        dns_str_to_record_type(json_object["type"].get<json::string_t>());
    data.rdata = json_object["info"].get<json::string_t>();
    data.ttl = json_object["ttl"].get<json::number_integer_t>();
    data.content_length = len;
    data.http_code = http_code;
    if (auto const iter = json_object.find("first-seen");
        iter != json_object.end()) {
      data.first_seen = iter->second.get<json::string_t>();
    }
    if (auto const iter = json_object.find("last-seen");
        iter != json_object.end()) {
      data.last_seen = iter->second.get<json::string_t>();
    }
    if (auto const iter = json_object.find("seen"); iter != json_object.end()) {
      data.seen = iter->second.get<json::number_integer_t>();
    }
    return data;
  }
};

struct jd_domain_comparator_t {
  bool operator()(json_data_t const &a, json_data_t const &b) const {
    return a.domain_name < b.domain_name;
  }
};

namespace detail {

inline std::string lower_copy(std::string value) {
  std::transform(value.begin(), value.end(), value.begin(),
                 [](unsigned char ch) { return (char)std::tolower(ch); });
  return value;
}

inline std::string history_key(std::string const &domain_name,
                               dns_record_type_e const type,
                               std::string const &rdata) {
  return lower_copy(domain_name) + "\n" + std::to_string((int)type) + "\n" +
         lower_copy(rdata);
}

inline std::string history_key(json_data_t const &record) {
  return history_key(record.domain_name, record.type, record.rdata);
}

inline std::string history_key(std::string const &domain_name,
                               probe_result_t const &record) {
  return history_key(domain_name, record.type, record.rdata);
}

inline json::object_t json_with_history(probe_result_t const &record,
                                        std::string const &first_seen,
                                        std::string const &last_seen,
                                        int const seen) {
  json record_json = record;
  auto record_object = record_json.get<json::object_t>();
  record_object["first-seen"] = first_seen;
  record_object["last-seen"] = last_seen;
  record_object["seen"] = seen;
  return record_object;
}

inline json::object_t json_from_history(json_data_t const &record,
                                        std::string const &scan_date) {
  auto first_seen = record.first_seen;
  auto last_seen = record.last_seen;
  auto seen = record.seen;
  if (first_seen.empty()) {
    first_seen = last_seen.empty() ? scan_date : last_seen;
  }
  if (last_seen.empty()) {
    last_seen = first_seen.empty() ? scan_date : first_seen;
  }
  if (seen <= 0) {
    seen = 1;
  }

  json::object_t object;
  object["ttl"] = record.ttl;
  object["type"] = dns_record_type_to_str(record.type);
  object["info"] = record.rdata;
  object["first-seen"] = std::move(first_seen);
  object["last-seen"] = std::move(last_seen);
  object["seen"] = seen;
  return object;
}

template <typename DnsType, typename RtType>
void write_json_result_impl(map_container_t<DnsType> const &result_map,
                            RtType const &rt_args) {
  bool const has_previous =
      rt_args.previous_data && !rt_args.previous_data->empty();
  if (result_map.empty() && !has_previous) {
    std::error_code ec{};
    if (std::filesystem::exists(rt_args.output_filename) &&
        !std::filesystem::remove(rt_args.output_filename, ec)) {
      printf("unable to remove %s", rt_args.output_filename.c_str());
    }
    return;
  }

  std::map<std::string, json_data_t> previous_lookup;
  std::map<std::string, std::vector<json_data_t>> previous_by_domain;
  if (has_previous) {
    for (auto const &record : *rt_args.previous_data) {
      previous_lookup[history_key(record)] = record;
      previous_by_domain[record.domain_name].push_back(record);
    }
  }

  auto const scan_date =
      rt_args.scan_date.empty() ? std::string{"unknown"} : rt_args.scan_date;

  json::array_t list;
  std::set<std::string> emitted_keys;
  for (auto const &result_pair : result_map.cresult()) {
    json::object_t internal_object;
    auto &http_result = result_pair.second.http_result_;
    json::array_t dns_probe_list;
    for (auto const &record : result_pair.second.dns_result_list_) {
      auto const key = history_key(result_pair.first, record);
      emitted_keys.insert(key);
      auto first_seen = scan_date;
      auto seen = 1;
      if (auto const iter = previous_lookup.find(key);
          iter != previous_lookup.end()) {
        first_seen = iter->second.first_seen.empty()
                         ? (iter->second.last_seen.empty()
                                ? scan_date
                                : iter->second.last_seen)
                         : iter->second.first_seen;
        seen = (std::max)(iter->second.seen, 0) + 1;
      }
      dns_probe_list.push_back(
          json_with_history(record, first_seen, scan_date, seen));
    }
    if (auto const iter = previous_by_domain.find(result_pair.first);
        iter != previous_by_domain.end()) {
      for (auto const &record : iter->second) {
        auto const key = history_key(record);
        if (emitted_keys.find(key) == emitted_keys.end()) {
          emitted_keys.insert(key);
          dns_probe_list.push_back(json_from_history(record, scan_date));
        }
      }
    }

    internal_object["dns_probe"] = std::move(dns_probe_list);
    internal_object["content_length"] = http_result.content_length_;
    internal_object["http_code"] = http_result.http_status_;
    internal_object["code_string"] = code_string(http_result.http_status_);

    json::object_t object;
    object[result_pair.first] = internal_object;
    list.push_back(std::move(object));
  }
  if (has_previous) {
    for (auto const &result_pair : previous_by_domain) {
      auto const current_iter = result_map.cresult().find(result_pair.first);
      if (current_iter != result_map.cresult().end()) {
        continue;
      }

      json::array_t dns_probe_list;
      auto content_length = 0;
      auto http_code = 0;
      for (auto const &record : result_pair.second) {
        auto const key = history_key(record);
        if (emitted_keys.find(key) != emitted_keys.end()) {
          continue;
        }
        emitted_keys.insert(key);
        content_length = record.content_length;
        http_code = record.http_code;
        dns_probe_list.push_back(json_from_history(record, scan_date));
      }
      if (dns_probe_list.empty()) {
        continue;
      }

      json::object_t internal_object;
      internal_object["dns_probe"] = std::move(dns_probe_list);
      internal_object["content_length"] = content_length;
      internal_object["http_code"] = http_code;
      internal_object["code_string"] = code_string(http_code);

      json::object_t object;
      object[result_pair.first] = std::move(internal_object);
      list.push_back(std::move(object));
    }
  }
  json::object_t res_object;

  res_object["program"] = "dooked";
  res_object["result"] = std::move(list);
  (*rt_args.output_file) << json(res_object).dump(2) << "\n";
  rt_args.output_file->close();
}

template <typename T, typename Iterator>
std::optional<std::vector<T>> read_json_string(Iterator const begin,
                                               Iterator const end) {
  std::vector<T> result{};

  try {

    json json_content = json::parse(begin, end);
    auto object_root = json_content.get<json::object_t>();
    auto const result_list = object_root["result"].get<json::array_t>();

    for (auto const &result_item : result_list) {
      auto json_object = result_item.get<json::object_t>();

      for (auto const json_item : json_object) {
        std::string const domain_name = json_item.first;
        auto internal_object = json_item.second.get<json::object_t>();
        auto const domain_detail_list =
            internal_object["dns_probe"].get<json::array_t>();
        auto const content_length =
            internal_object["content_length"].get<json::number_integer_t>();
        auto const http_code =
            internal_object["http_code"].get<json::number_integer_t>();

        for (auto const &domain_detail : domain_detail_list) {
          auto domain_object = domain_detail.get<json::object_t>();
          result.push_back(T::serialize(domain_name, content_length, http_code,
                                        domain_object));
        }
      }
    }
  } catch (std::runtime_error const &e) {
    puts(e.what());
    return std::nullopt;
  }
  return result;
}

template <typename T>
std::optional<std::vector<T>>
read_json_file(std::filesystem::path const &file_path) {
  std::ifstream input_file(file_path);
  if (!input_file) {
    return std::nullopt;
  }
  auto const file_size = std::filesystem::file_size(file_path);
  std::vector<char> file_buffer(file_size);
  input_file.read(&file_buffer[0], file_size);
  return read_json_string<T>(file_buffer.cbegin(), file_buffer.cend());
}

template <typename T>
opt_list_t<T> read_text_file(std::filesystem::path const &file_path) {
  std::ifstream input_file(file_path);
  if (!input_file) {
    return std::nullopt;
  }
  std::vector<T> domain_names{};
  std::string line{};
  while (std::getline(input_file, line)) {
    trim(line);
    if (line.empty()) {
      continue;
    }
    domain_names.push_back({line});
  }
  return domain_names;
}

} // namespace detail

template <typename T>
opt_list_t<T> get_names(std::string const &filename,
                        file_type_e const file_type = file_type_e::txt_type) {
  bool const using_stdin = filename.empty();

  // read line by line and send the result back as-is.
  if (using_stdin && file_type == file_type_e::txt_type) { // use stdin
    std::string domain_name{};
    std::vector<T> domain_names;
    while (std::getline(std::cin, domain_name)) {
      domain_names.push_back({domain_name});
    }
    return domain_names;

    // read line by line but parse the JSON result
  } else if (using_stdin && file_type == file_type_e::json_type) {
    std::ostringstream ss{};
    std::string line{};
    while (std::getline(std::cin, line)) {
      ss << line;
    }
    auto const buffer{ss.str()};
    if constexpr (!std::is_same_v<T, std::string>) {
      return detail::read_json_string<T>(buffer.cbegin(), buffer.cend());
    }
    return std::nullopt;
  } else if (using_stdin) {
    return std::nullopt;
  }

  std::filesystem::path const file{filename};
  if (!std::filesystem::exists(file)) {
    return std::nullopt;
  }
  switch (file_type) {
  case file_type_e::txt_type:
    return detail::read_text_file<T>(file);
  case file_type_e::json_type:
    if constexpr (!std::is_same_v<T, std::string>) {
      return detail::read_json_file<T>(file);
    }
  }
  // if we are here, we were unable to determine the type
  auto const file_extension{get_file_type(file)};
  if (is_text_file(file_extension)) {
    return detail::read_text_file<T>(file);
  } else if (is_json_file(file_extension)) {
    if constexpr (!std::is_same_v<T, std::string>) {
      return detail::read_json_file<T>(file);
    }
  }
  // if file extension/type cannot be determined, read as TXT file
  return detail::read_text_file<T>(file);
}

template <typename DnsType, typename RtType>
void write_json_result(map_container_t<DnsType> const &result_map,
                       RtType const &rt_args) {
  return detail::write_json_result_impl(result_map, rt_args);
}
} // namespace dooked
