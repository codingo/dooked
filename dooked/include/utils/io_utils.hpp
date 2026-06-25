#pragma once

#include "utils/containers.hpp"
#include "utils/probe_result.hpp"
#include <algorithm>
#include <cctype>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <nlohmann/json.hpp>
#include <optional>
#include <set>
#include <sstream>
#include <tuple>

namespace dooked {

using json = nlohmann::json;
template <typename T> using opt_list_t = std::optional<std::vector<T>>;

void to_json(json &j, probe_result_t const &record);
dns_record_type_e dns_str_to_record_type(std::string const &);
bool is_text_file(std::string const &file_extension);
bool is_json_file(std::string const &file_extension);
std::string get_file_type(std::filesystem::path const &file_path);
std::string get_filepath(std::string const &filename);
std::string current_us_datetime();
std::uint16_t uint16_value(unsigned char const *buff);
void trim(std::string &);

struct json_data_t {
  std::string domain_name{};
  std::string rdata{};
  std::string first_seen{};
  std::string last_seen{};
  int seen{};
  bool currently_seen{true};
  int ttl{};
  int http_code{};
  int content_length{};
  dns_record_type_e type{};

  static json_data_t serialize(std::string const &d, int const len,
                               int const http_code,
                               json::object_t &json_object) {
    json_data_t data{};
    data.domain_name = d;
    data.type =
        dns_str_to_record_type(json_object["type"].get<json::string_t>());
    data.rdata = json_object["info"].get<json::string_t>();
    data.ttl =
        static_cast<int>(json_object["ttl"].get<json::number_integer_t>());
    data.content_length = len;
    data.http_code = http_code;

    auto const read_optional_string = [&json_object](char const *key) {
      auto const iter = json_object.find(key);
      if (iter != json_object.cend() && iter->second.is_string()) {
        return iter->second.get<json::string_t>();
      }
      return std::string{};
    };
    auto const read_optional_int = [&json_object](char const *key) {
      auto const iter = json_object.find(key);
      if (iter != json_object.cend() && iter->second.is_number_integer()) {
        return iter->second.get<json::number_integer_t>();
      }
      return json::number_integer_t{};
    };
    auto const read_optional_bool = [&json_object](char const *key,
                                                   bool const fallback) {
      auto const iter = json_object.find(key);
      if (iter != json_object.cend() && iter->second.is_boolean()) {
        return iter->second.get<json::boolean_t>();
      }
      return fallback;
    };

    data.first_seen = read_optional_string("first-seen");
    if (data.first_seen.empty()) {
      data.first_seen = read_optional_string("first_seen");
    }
    data.last_seen = read_optional_string("last-seen");
    if (data.last_seen.empty()) {
      data.last_seen = read_optional_string("last_seen");
    }
    data.seen = static_cast<int>(read_optional_int("seen"));
    data.currently_seen = read_optional_bool("currently-seen", true);
    data.currently_seen = read_optional_bool("currently_seen",
                                             data.currently_seen);
    return data;
  }
};

struct jd_domain_comparator_t {
  bool operator()(json_data_t const &a, json_data_t const &b) const {
    return a.domain_name < b.domain_name;
  }
};

namespace detail {

using json_record_key_t = std::tuple<std::string, dns_record_type_e, std::string>;
using previous_record_index_t = std::map<json_record_key_t, json_data_t>;
using previous_record_group_t = std::map<std::string, std::vector<json_data_t>>;

inline std::string lowercase_copy(std::string value) {
  std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
    return static_cast<char>(std::tolower(c));
  });
  return value;
}

inline json_record_key_t make_json_record_key(std::string domain_name,
                                              dns_record_type_e const type,
                                              std::string rdata) {
  return {lowercase_copy(std::move(domain_name)), type,
          lowercase_copy(std::move(rdata))};
}

inline previous_record_index_t make_previous_record_index(
    std::optional<std::vector<json_data_t>> const &previous_data) {
  previous_record_index_t index{};
  if (!previous_data) {
    return index;
  }
  for (auto const &record : *previous_data) {
    index[make_json_record_key(record.domain_name, record.type, record.rdata)] =
        record;
  }
  return index;
}

inline previous_record_group_t make_previous_record_groups(
    std::optional<std::vector<json_data_t>> const &previous_data) {
  previous_record_group_t groups{};
  if (!previous_data) {
    return groups;
  }
  for (auto const &record : *previous_data) {
    groups[lowercase_copy(record.domain_name)].push_back(record);
  }
  return groups;
}

inline json::object_t make_historical_dns_record_json(
    json_data_t const &previous_record, std::string const &current_datetime) {
  json::object_t dns_object;
  dns_object["ttl"] = previous_record.ttl;
  dns_object["type"] = dns_record_type_to_str(previous_record.type);
  dns_object["info"] = previous_record.rdata;

  auto first_seen = previous_record.first_seen;
  if (first_seen.empty()) {
    first_seen = previous_record.last_seen.empty() ? current_datetime
                                                   : previous_record.last_seen;
  }
  auto last_seen = previous_record.last_seen.empty() ? first_seen
                                                     : previous_record.last_seen;
  dns_object["first-seen"] = std::move(first_seen);
  dns_object["last-seen"] = std::move(last_seen);
  dns_object["seen"] = previous_record.seen > 0 ? previous_record.seen : 1;
  dns_object["currently-seen"] = false;
  return dns_object;
}

template <typename DnsType>
json::object_t make_dns_record_json(
    std::string const &domain_name, DnsType const &dns_record,
    previous_record_index_t const &previous_record_index,
    std::string const &current_datetime) {
  json::object_t dns_object;
  dns_object["ttl"] = dns_record.ttl;
  dns_object["type"] = dns_record_type_to_str(dns_record.type);
  dns_object["info"] = dns_record.rdata;

  auto const key =
      make_json_record_key(domain_name, dns_record.type, dns_record.rdata);
  auto const previous_record_iter = previous_record_index.find(key);
  if (previous_record_iter == previous_record_index.cend()) {
    dns_object["first-seen"] = current_datetime;
    dns_object["last-seen"] = current_datetime;
    dns_object["seen"] = 1;
    dns_object["currently-seen"] = true;
    return dns_object;
  }

  auto const &previous_record = previous_record_iter->second;
  auto first_seen = previous_record.first_seen;
  if (first_seen.empty()) {
    first_seen = previous_record.last_seen.empty() ? current_datetime
                                                   : previous_record.last_seen;
  }
  dns_object["first-seen"] = std::move(first_seen);
  dns_object["last-seen"] = current_datetime;
  dns_object["seen"] = previous_record.seen > 0 ? previous_record.seen + 1 : 2;
  dns_object["currently-seen"] = true;
  return dns_object;
}

template <typename DnsType, typename RtType>
void write_json_result_impl(map_container_t<DnsType> const &result_map,
                            RtType const &rt_args) {
  if (result_map.empty()) {
    std::error_code ec{};
    if (std::filesystem::exists(rt_args.output_filename) &&
        !std::filesystem::remove(rt_args.output_filename, ec)) {
      printf("unable to remove %s", rt_args.output_filename.c_str());
    }
    return;
  }

  json::array_t list;
  auto const previous_record_index =
      make_previous_record_index(rt_args.previous_data);
  auto const previous_record_groups =
      make_previous_record_groups(rt_args.previous_data);
  auto const current_datetime = current_us_datetime();
  std::set<std::string> output_domain_keys;
  for (auto const &result_pair : result_map.cresult()) {
    json::object_t internal_object;
    auto &http_result = result_pair.second.http_result_;
    json::array_t dns_probe_list;
    std::set<json_record_key_t> current_record_keys;
    for (auto const &dns_record : result_pair.second.dns_result_list_) {
      current_record_keys.insert(make_json_record_key(
          result_pair.first, dns_record.type, dns_record.rdata));
      dns_probe_list.push_back(make_dns_record_json(
          result_pair.first, dns_record, previous_record_index, current_datetime));
    }

    auto const domain_key = lowercase_copy(result_pair.first);
    output_domain_keys.insert(domain_key);
    auto const previous_group_iter = previous_record_groups.find(domain_key);
    if (previous_group_iter != previous_record_groups.cend()) {
      for (auto const &previous_record : previous_group_iter->second) {
        auto const record_key = make_json_record_key(
            previous_record.domain_name, previous_record.type, previous_record.rdata);
        if (current_record_keys.find(record_key) != current_record_keys.cend()) {
          continue;
        }
        dns_probe_list.push_back(
            make_historical_dns_record_json(previous_record, current_datetime));
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

  for (auto const &previous_group_pair : previous_record_groups) {
    if (output_domain_keys.find(previous_group_pair.first) !=
        output_domain_keys.cend()) {
      continue;
    }
    auto const &records = previous_group_pair.second;
    if (records.empty()) {
      continue;
    }

    json::array_t dns_probe_list;
    for (auto const &previous_record : records) {
      dns_probe_list.push_back(
          make_historical_dns_record_json(previous_record, current_datetime));
    }

    auto const &first_record = records.front();
    json::object_t internal_object;
    internal_object["dns_probe"] = std::move(dns_probe_list);
    internal_object["content_length"] = first_record.content_length;
    internal_object["http_code"] = first_record.http_code;
    internal_object["code_string"] = code_string(first_record.http_code);

    json::object_t object;
    object[first_record.domain_name] = std::move(internal_object);
    list.push_back(std::move(object));
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
        auto const content_length = static_cast<int>(
            internal_object["content_length"].get<json::number_integer_t>());
        auto const http_code = static_cast<int>(
            internal_object["http_code"].get<json::number_integer_t>());

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
