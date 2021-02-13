#pragma once

#include "utils/containers.hpp"
#include "utils/probe_result.hpp"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <nlohmann/json.hpp>
#include <optional>
#include <sstream>

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
    return data;
  }
};

struct jd_domain_comparator_t {
  bool operator()(json_data_t const &a, json_data_t const &b) const {
    return a.domain_name < b.domain_name;
  }
};

namespace detail {

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
  for (auto const &result_pair : result_map.cresult()) {
    json::object_t internal_object;
    auto &http_result = result_pair.second.http_result_;
    internal_object["dns_probe"] = result_pair.second.dns_result_list_;
    internal_object["content_length"] = http_result.content_length_;
    internal_object["http_code"] = http_result.http_status_;
    internal_object["code_string"] = code_string(http_result.http_status_);

    json::object_t object;
    object[result_pair.first] = internal_object;
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
