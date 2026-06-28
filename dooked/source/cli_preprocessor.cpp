#include "cli_preprocessor.hpp"
#include "dns/dns_resolver.hpp"
#include "http/resolver.hpp"
#include "utils/exceptions.hpp"
#include "utils/random_utils.hpp"
#include "utils/string_utils.hpp"
#include <algorithm>
#include <boost/asio/io_context.hpp>
#include <boost/asio/thread_pool.hpp>
#include <ctime>
#include <iomanip>
#include <set>
#include <spdlog/spdlog.h>
#include <sstream>

// defined (and assigned to) in main.cpp
extern bool silent;
extern bool compare_cl;

namespace dooked {

namespace net = boost::asio;
using namespace fmt::v7::literals;

std::string history_date_string(std::time_t const timestamp = std::time(nullptr)) {
  std::string output{};
  if (!timet_to_string(output, timestamp, "%m/%d/%Y")) {
    return {};
  }
  return output;
}

std::optional<std::time_t> parse_history_date(std::string const &date_string) {
  if (date_string.empty()) {
    return std::nullopt;
  }
  std::tm tm{};
  std::istringstream input{date_string};
  input >> std::get_time(&tm, "%m/%d/%Y");
  if (input.fail()) {
    return std::nullopt;
  }
  tm.tm_hour = 23;
  tm.tm_min = 59;
  tm.tm_sec = 59;
  return std::mktime(&tm);
}

std::optional<std::time_t> days_before_now(int const days) {
  if (days < 0) {
    return std::nullopt;
  }
  return std::time(nullptr) - (static_cast<std::time_t>(days) * 24 * 60 * 60);
}

bool records_match(json_data_t const &previous, probe_result_t const &current) {
  return previous.type == current.type &&
         case_insensitive_compare(previous.rdata, current.rdata);
}

bool records_match(json_data_t const &previous,
                   std::string const &domain_name,
                   probe_result_t const &current) {
  return case_insensitive_compare(previous.domain_name, domain_name) &&
         records_match(previous, current);
}

bool history_record_less(json_data_t const &a, json_data_t const &b) {
  return std::tie(a.domain_name, a.type, a.rdata) <
         std::tie(b.domain_name, b.type, b.rdata);
}

bool probe_record_less(probe_result_t const &a, probe_result_t const &b) {
  return std::tie(a.type, a.rdata) < std::tie(b.type, b.rdata);
}

void sort_domain_records(http_dns_response_t<probe_result_t> &domain_result) {
  std::sort(domain_result.dns_result_list_.begin(),
            domain_result.dns_result_list_.end(), probe_record_less);
}

std::string first_seen_or_today(json_data_t const &record,
                                std::string const &today) {
  return record.first_seen.empty() ? today : record.first_seen;
}

std::string last_seen_or_today(json_data_t const &record,
                               std::string const &today) {
  return record.last_seen.empty() ? today : record.last_seen;
}

bool should_report_last_seen(json_data_t const &previous_record,
                             runtime_args_t const &rt_args) {
  if (rt_args.last_seen_days < 0 && !rt_args.last_seen_cutoff) {
    return false;
  }
  if (previous_record.last_seen.empty()) {
    return true;
  }

  auto const last_seen = parse_history_date(previous_record.last_seen);
  if (!last_seen) {
    return true;
  }

  if (rt_args.last_seen_cutoff && *last_seen <= *rt_args.last_seen_cutoff) {
    return true;
  }
  if (auto const days_cutoff = days_before_now(rt_args.last_seen_days);
      days_cutoff && *last_seen <= *days_cutoff) {
    return true;
  }
  return false;
}

void report_history_changes(
    std::vector<json_data_t>::const_iterator previous_begin,
    std::vector<json_data_t>::const_iterator previous_end,
    std::string const &domain_name,
    std::vector<probe_result_t> const &current_records,
    runtime_args_t const &rt_args) {
  if (rt_args.first_seen) {
    auto const today = history_date_string();
    for (auto const &current_record : current_records) {
      auto const previous_iter =
          std::find_if(previous_begin, previous_end, [&](auto const &previous) {
            return records_match(previous, current_record);
          });
      if (previous_iter == previous_end) {
        spdlog::info("[FIRST-SEEN][{}][{}] `{}` first seen {}", domain_name,
                     dns_record_type_to_str(current_record.type),
                     current_record.rdata, today);
      }
    }
  }

  for (auto iter = previous_begin; iter != previous_end; ++iter) {
    auto const current_iter =
        std::find_if(current_records.cbegin(), current_records.cend(),
                     [&](auto const &current) {
                       return records_match(*iter, current);
                     });
    if (current_iter == current_records.cend() &&
        should_report_last_seen(*iter, rt_args)) {
      spdlog::info("[LAST-SEEN][{}][{}] `{}` last seen {}", domain_name,
                   dns_record_type_to_str(iter->type), iter->rdata,
                   iter->last_seen.empty() ? "unknown" : iter->last_seen);
    }
  }
}

void apply_history_metadata(std::optional<std::vector<json_data_t>> const &previous,
                            map_container_t<probe_result_t> &result_map,
                            std::string const &today) {
  auto &current_data = result_map.result();
  for (auto &[domain_name, domain_result] : current_data) {
    for (auto &record : domain_result.dns_result_list_) {
      if (previous) {
        auto const previous_iter =
            std::find_if(previous->cbegin(), previous->cend(),
                         [&](auto const &previous_record) {
                           return records_match(previous_record, domain_name,
                                                record);
                         });
        if (previous_iter != previous->cend()) {
          record.first_seen = first_seen_or_today(*previous_iter, today);
          record.last_seen = today;
          record.seen_count =
              previous_iter->seen_count > 0 ? previous_iter->seen_count + 1 : 2;
          continue;
        }
      }

      record.first_seen = today;
      record.last_seen = today;
      record.seen_count = 1;
    }
  }

  if (!previous) {
    return;
  }

  for (auto const &previous_record : *previous) {
    auto const current_domain_iter = current_data.find(previous_record.domain_name);
    auto const found_current =
        current_domain_iter != current_data.end() &&
        std::find_if(current_domain_iter->second.dns_result_list_.cbegin(),
                     current_domain_iter->second.dns_result_list_.cend(),
                     [&](auto const &current_record) {
                       return records_match(previous_record, current_record);
                     }) != current_domain_iter->second.dns_result_list_.cend();

    if (found_current) {
      continue;
    }

    if (current_domain_iter == current_data.end()) {
      result_map.insert(previous_record.domain_name,
                        previous_record.content_length,
                        previous_record.http_code);
    }
    probe_result_t retained_record{};
    retained_record.rdata = previous_record.rdata;
    retained_record.type = previous_record.type;
    retained_record.ttl = static_cast<std::uint32_t>(previous_record.ttl);
    retained_record.first_seen = first_seen_or_today(previous_record, today);
    retained_record.last_seen = last_seen_or_today(previous_record, today);
    retained_record.seen_count =
        previous_record.seen_count > 0 ? previous_record.seen_count : 1;
    result_map.append(previous_record.domain_name, retained_record);
  }

  for (auto &[domain_name, domain_result] : current_data) {
    sort_domain_records(domain_result);
  }
}

void compare_http_result(int const base_cl, json_data_t const &prev_http_result,
                         http_response_t const &current_result) {
  auto const current_req_cl = current_result.content_length_;
  auto const current_req_http_code = current_result.http_status_;
  auto const previous_req_cl = prev_http_result.content_length;
  auto const previous_req_http_code = prev_http_result.http_code;

  if (compare_cl) {
    // check if content-length's changed
    bool const baseline_specified = base_cl != -1;
    if ((baseline_specified && (current_req_cl > base_cl)) ||
        ((!baseline_specified) && current_req_cl != previous_req_cl)) {
      spdlog::info("[CHANGED][CONTENT-LENGTH][{}] from `{}` to `{}`",
                   prev_http_result.domain_name, previous_req_cl,
                   current_req_cl);
    }
  }
  // the HTTP code has changed
  if (previous_req_http_code == 200 && current_req_http_code != 200) {
    if (current_req_http_code ==
        (int)response_type_e::cannot_resolve_name) { // special case
      spdlog::info("[CHANGED][HTTP CODE][{}] used to resolve but now doesn't",
                   prev_http_result.domain_name);
    } else {
      spdlog::info("[CHANGED][HTTP CODE][{}] from `{}` to `{}`",
                   prev_http_result.domain_name,
                   code_string(previous_req_http_code),
                   code_string(current_req_http_code));
    }
  }
}

[[nodiscard]] std::vector<json_data_t>::const_iterator compare_dns_result(
    std::vector<json_data_t>::const_iterator iter,
    std::vector<json_data_t>::const_iterator end_iter,
    http_dns_response_t<probe_result_t> const &current_domain_info,
    runtime_args_t const &rt_args,
    jd_domain_comparator_t const &domain_comparator) {

  auto const last_elem_iter =
      std::upper_bound(iter, end_iter, *iter, domain_comparator);
  auto const previous_total_elem =
      (std::size_t)std::distance(iter, last_elem_iter);
  auto const &current_domain_info_list = current_domain_info.dns_result_list_;
  auto const current_total_elem = current_domain_info_list.size();
  report_history_changes(iter, last_elem_iter, iter->domain_name,
                         current_domain_info_list, rt_args);

  // something is missing
  if (current_total_elem < previous_total_elem) {
    for (auto start_iter = iter; start_iter != last_elem_iter; ++start_iter) {
      bool const found =
          std::find_if(current_domain_info_list.cbegin(),
                       current_domain_info_list.cend(),
                       [&](auto const &current_record) {
                         return records_match(*start_iter, current_record);
                       }) != current_domain_info_list.cend();
      if (!found) {
        spdlog::error("[MISSING][{}][{}] `{}`", iter->domain_name,
                      dns_record_type_to_str(start_iter->type),
                      start_iter->rdata);
      }
    }
    // information may have been changed
  } else if (current_total_elem == previous_total_elem) {
    auto record_type = dns_record_type_e::DNS_REC_UNDEFINED;
    for (auto start_iter = iter; start_iter != last_elem_iter; ++start_iter) {
      // find records of the same type: A, AAAA, MX, NS...
      auto const eq_range = std::equal_range(
          current_domain_info_list.cbegin(), current_domain_info_list.cend(),
          *start_iter,
          [](auto const &a, auto const &b) { return a.type < b.type; });
      // see if the data is the same.
      auto const find_iter = std::find_if(
          eq_range.first, eq_range.second,
          [&val = *start_iter](auto const &record) {
            return case_insensitive_compare(val.rdata, record.rdata);
          });
      // if we cannot find it
      if (find_iter == eq_range.second) {
        auto const distance = std::distance(eq_range.first, eq_range.second);
        if (distance == 0) {
          spdlog::error("[REMOVED][{}][{}] `{}`", iter->domain_name,
                        dns_record_type_to_str(start_iter->type),
                        start_iter->rdata);
        } else if (distance == 1) {
          spdlog::info("[CHANGED][{}][{}] from `{}` to `{}`", iter->domain_name,
                       dns_record_type_to_str(start_iter->type),
                       start_iter->rdata, eq_range.first->rdata);
        } else {
          if (record_type != iter->type) {
            record_type = iter->type;
            for (auto current_range = eq_range.first;
                 current_range != eq_range.second; ++current_range) {
              spdlog::info("[NEW][{}][{}] `{}`", iter->domain_name,
                           dns_record_type_to_str(current_range->type),
                           current_range->rdata);
            }
          }
        }
      }
    }
  } else {
    // new information has been added
    for (auto const &current_elem : current_domain_info_list) {
      bool const found =
          std::find_if(iter, last_elem_iter, [&](auto const &previous_record) {
            return records_match(previous_record, current_elem);
          }) != last_elem_iter;
      if (!found) {
        spdlog::info("[NEW][{}][{}] `{}`", iter->domain_name,
                     dns_record_type_to_str(current_elem.type),
                     current_elem.rdata);
      }
    }
  }
  compare_http_result(rt_args.content_length, *iter,
                      current_domain_info.http_result_);
  return last_elem_iter;
}

void compare_results(std::vector<json_data_t> const &previous_result,
                     map_container_t<probe_result_t> const &current_result,
                     runtime_args_t const &rt_args) {
  if (!silent) {
    spdlog::info("Trying to compare old with new result");
  }
  // previous data is already sorted.
  // current data is a pre-sorted data.
  auto const &current_data_map = current_result.cresult();
  auto const end_iter = previous_result.cend();
  auto const domain_comparator = jd_domain_comparator_t{};

  // %^ designate color start,
  // %$ designates the end of color,
  // %v is the message we want to log.
  spdlog::set_pattern("[%^CHECK%$] %v");

  for (auto iter = previous_result.cbegin(); iter < end_iter;) {
    auto const current_find_iter = current_data_map.find(iter->domain_name);
    if (current_find_iter == current_data_map.end()) {
      spdlog::error("{} not found in new result", iter->domain_name);
      // find the next domain name following this current domain
      auto const next_iter =
          std::upper_bound(iter, end_iter, *iter, domain_comparator);
      report_history_changes(iter, next_iter, iter->domain_name, {}, rt_args);
      iter = next_iter;
      continue;
    }
    auto const &current_domain_info = current_find_iter->second;
    auto next_iter = compare_dns_result(iter, end_iter, current_domain_info,
                                        rt_args, domain_comparator);
    iter = next_iter;
  }
}

void dns_functor(net::io_context &io_context, net::ssl::context *ssl_context,
                 runtime_args_t &rt_args,
                 map_container_t<probe_result_t> &result_map,
                 std::size_t const socket_count, bool const deferring) {
  std::vector<std::unique_ptr<custom_resolver_socket_t>> sockets{};
  sockets.resize(socket_count);
  for (std::size_t i = 0; i < socket_count; ++i) {
    sockets[i] = std::make_unique<custom_resolver_socket_t>(
        io_context, ssl_context, *rt_args.names, *rt_args.resolvers,
        result_map);
    sockets[i]->defer_http_request(deferring);
    sockets[i]->start();
  }
  io_context.run();
}

void http_functor(net::io_context &io_context, net::ssl::context *ssl_context,
                  runtime_args_t &rt_args,
                  map_container_t<probe_result_t> &result_map,
                  std::size_t const socket_count) {
  std::vector<std::unique_ptr<http_resolver_t>> sockets{};
  sockets.resize(socket_count);
  for (std::size_t i = 0; i < socket_count; ++i) {
    sockets[i] = std::make_unique<http_resolver_t>(io_context, ssl_context,
                                                   *rt_args.names, result_map);
    sockets[i]->start();
  }
  io_context.run();
}

bool process_text_file(std::string const &input_filename,
                       runtime_args_t &rt_args) {
  auto domain_names = get_names<std::string>(input_filename);
  if (domain_names && !domain_names->empty()) {
    rt_args.names.emplace();
    for (auto const &domain_name : *domain_names) {
      rt_args.names->push_back({domain_name});
    }
  } else {
    spdlog::error("There was an error trying to get input file");
    return false;
  }
  return true;
}

bool process_json_file(std::string const &input_filename,
                       runtime_args_t &rt_args) {
  rt_args.previous_data =
      get_names<json_data_t>(input_filename, file_type_e::json_type);
  auto &previous_records = rt_args.previous_data;
  if (previous_records && !previous_records->empty()) {
    std::set<std::string> unique_names{};
    for (auto const &domain_name : *previous_records) {
      unique_names.insert(domain_name.domain_name);
    }
    rt_args.names.emplace();
    for (auto const &name : unique_names) {
      rt_args.names->push_back(name);
    }
  } else {
    spdlog::error("There was an error trying to get input file");
    return false;
  }
  return true;
}

// most likely from stdin
bool determine_unknown_file(cli_args_t const &cli_args,
                            runtime_args_t &rt_args) {
  bool const using_stdin = cli_args.input_filename.empty();
  if (!using_stdin) {
    return false;
  }
  auto const filename = std::filesystem::temp_directory_path() /
                        get_random_string(get_random_integer());
  std::ofstream temp_file{filename};
  if (!temp_file) {
    spdlog::error("unable to open temporary file");
    return false;
  }
  std::string line{};
  while (std::getline(std::cin, line)) {
    temp_file << line;
  }
  auto const file_type = get_file_type(filename);
  std::error_code ec{};
  // read the file and remove the temporary file thereafter
  if (is_text_file(file_type)) {
    return (process_text_file(filename.string(), rt_args) &&
            std::filesystem::remove(filename, ec));
  } else if (is_json_file(file_type)) {
    return process_json_file(filename.string(), rt_args) &&
           std::filesystem::remove(filename, ec);
  }
  return false;
}

bool read_input_file(cli_args_t const &cli_args, runtime_args_t &rt_args) {
  bool const using_stdin = cli_args.input_filename.empty();
  if (using_stdin) {
    auto const file_type = static_cast<file_type_e>(cli_args.file_type);
    if (file_type == file_type_e::txt_type) {
      return process_text_file(cli_args.input_filename, rt_args);
    } else if (file_type == file_type_e::json_type) {
      return process_json_file(cli_args.input_filename, rt_args);
    }
    return determine_unknown_file(cli_args, rt_args);
  }

  auto const file_type = get_file_type(cli_args.input_filename);
  if (is_text_file(file_type)) {
    return process_text_file(cli_args.input_filename, rt_args);
  } else if (is_json_file(file_type)) {
    return process_json_file(cli_args.input_filename, rt_args);
  }
  return false;
}

void start_name_checking(runtime_args_t &&rt_args) {
  std::size_t const user_specified_thread =
      (rt_args.thread_count > 0) ? (std::size_t)rt_args.thread_count
                                 : DOOKED_SUPPORTED_THREADS;
  auto const thread_count =
      (std::min)(rt_args.names->size(), user_specified_thread);

  auto const max_open_sockets =
      (std::min)(rt_args.names->size(), (thread_count * 2));
  // minimum of 1 socket per thread
  auto const sockets_per_thread =
      (std::max)(1, (int)(max_open_sockets / thread_count));

  if (!silent) {
    spdlog::info("Native thread count: {}", thread_count);
    spdlog::info("Sockets per thread: {}", sockets_per_thread);
    spdlog::info("Total input: {}", rt_args.names->size());
  }

  bool const using_lock = (thread_count > 1);
  map_container_t<probe_result_t> result_map(using_lock);
  bool const deferring = rt_args.http_request_time_ == http_process_e::deferred;

  // by default, we use tls v1.2, and only switch to 1.3 if 1.2 fails
  net::ssl::context ssl_context(net::ssl::context::tlsv12_client);
  ssl_context.set_default_verify_paths();
  ssl_context.set_verify_mode(net::ssl::verify_none);
  ssl_context.set_options(net::ssl::context::default_workarounds |
                          net::ssl::context::no_sslv2 |
                          net::ssl::context::no_sslv3);
  decltype(rt_args.names) deferred_names_;

  if (deferring) { // copy the names before dns probing
    deferred_names_.emplace(rt_args.names->clone());
  }

  net::io_context io_context((int)thread_count);
  std::optional<net::thread_pool> thread_pool(std::in_place, thread_count);

  { // perform DNS record probing.
    for (std::size_t index = 0; index < thread_count; ++index) {
      net::post(*thread_pool, [&] {
        dns_functor(io_context, &ssl_context, rt_args, result_map,
                    sockets_per_thread, deferring);
      });
    }
    thread_pool->join();
  }

  // if we deferred HTTP/S "probe", now is the time to get to it
  if (deferring) {
    io_context.reset();
    thread_pool.emplace(thread_count);
    rt_args.names.emplace(std::move(*deferred_names_));
    for (std::size_t index = 0; index < thread_count; ++index) {
      net::post(*thread_pool, [&] {
        http_functor(io_context, &ssl_context, rt_args, result_map,
                     sockets_per_thread);
      });
    }
    thread_pool->join();
  }
  // compare old with new result -- only if we had previous record
  if (rt_args.previous_data) {
    auto &previous_data = *rt_args.previous_data;

    // sort by the same fields used by record equality before grouping domains
    std::sort(previous_data.begin(), previous_data.end(), history_record_less);
    auto &result = result_map.result();
    for (auto &res : result) {
      sort_domain_records(res.second);
    }
    compare_results(*rt_args.previous_data, result_map, rt_args);
  }

  apply_history_metadata(rt_args.previous_data, result_map,
                         history_date_string());
  if (!silent) {
    spdlog::info("Writing JSON output");
  }
  write_json_result(result_map, rt_args);
}

void run_program(cli_args_t const &cli_args) {
  runtime_args_t rt_args{};
  // settle resolvers.
  std::vector<std::string> resolver_strings{};
  if (cli_args.resolver_filename.empty()) {
    if (cli_args.resolver.empty()) {
      if (!silent) {
        spdlog::info("No resolver specified, using default");
      }
      resolver_strings.push_back("8.8.8.8 53");
    } else {
      split_string(cli_args.resolver, resolver_strings, ',');
    }
  } else {
    if (auto resolvers = get_names<std::string>(cli_args.resolver_filename);
        resolvers && !resolvers->empty()) {
      resolver_strings = std::move(*resolvers);
    } else {
      return spdlog::error("Unable to read file content");
    }
  }

  // read input file
  if (!read_input_file(cli_args, rt_args)) {
    return;
  }
  // try opening an output file
  {
    std::string filename{};
    auto const out_file_path{get_filepath(cli_args.output_filename)};
    bool const output_specified = !out_file_path.empty();
    if (!output_specified || cli_args.include_date) {
      std::string appended_time{};
      bool const time_obtained = timet_to_string(
          appended_time, std::time(nullptr), "%d_%m_%Y__%H_%M_%S");
      if (output_specified && time_obtained) {
        filename = "{}-{}.json"_format(out_file_path, appended_time);
      } else if (!output_specified && !time_obtained) {
        return spdlog::error("Unable to generate time for output name,"
                             "will use output filename only");
      } else if (!time_obtained && output_specified) {
        spdlog::warn("Unable to generate name for output file");
        filename = "{}.json"_format(out_file_path);
      } else if (!output_specified && time_obtained) {
        filename = "dooked-{}.json"_format(appended_time);
      }
    } else {
      filename = "{}.json"_format(out_file_path);
    }
    std::ofstream file{filename, std::ios::trunc};
    if (!file) {
      return spdlog::error("unable to open `{}` for out", filename);
    }
    if (!silent) {
      spdlog::info("Output filename: {}", filename);
    }
    rt_args.output_file = std::make_unique<std::ofstream>(std::move(file));
    rt_args.output_filename = std::move(filename);
  }

  // convert strings to UDP endpoints
#ifdef _DEBUG
  spdlog::info("Converting UDP endpoints");
#endif // _DEBUG
  std::vector<resolver_address_t> resolver_eps{};
  resolver_eps.reserve(resolver_strings.size());
  auto the_transformer = [](auto &&resolver) -> resolver_address_t {
    std::vector<std::string> split{};
    split_string(resolver, split, ' ');
    unsigned int port = 53;

    if (auto const split_size = split.size();
        (split_size < 1 || split_size > 2)) {
      throw general_exception_t{"invalid ip:port => " + resolver};
    }
    if (split.size() == 2) {
      port = std::stoul(split[1]);
    }
    trim(split[0]);
    boost::system::error_code ec{};
    auto const ip_address = net::ip::make_address(split[0], ec);
    if (ec) {
      throw general_exception_t{ec.message()};
    }
    net::ip::udp::endpoint const ep{ip_address, (std::uint16_t)port};
    return {ep};
  };
  try {
    for (auto const &resolver_string : resolver_strings) {
      resolver_eps.push_back(the_transformer(resolver_string));
    }
  } catch (std::exception const &e) {
    return spdlog::error(e.what());
  }
  rt_args.resolvers.emplace(std::move(resolver_eps));
  rt_args.http_request_time_ =
      static_cast<http_process_e>(cli_args.post_http_request);
  rt_args.thread_count = cli_args.thread_count;
  rt_args.content_length = cli_args.content_length;
  rt_args.first_seen = cli_args.first_seen;
  rt_args.last_seen_days = cli_args.last_seen_days;
  if (!cli_args.last_seen_date.empty()) {
    auto const parsed_date = parse_history_date(cli_args.last_seen_date);
    if (!parsed_date) {
      return spdlog::error("invalid --lsd date: expected MM/DD/YYYY");
    }
    rt_args.last_seen_cutoff = parsed_date;
  }
  return start_name_checking(std::move(rt_args));
}

void report_error(std::string const &message) { spdlog::error(message); }
void report_error(char const *format, std::string const &message) {
  spdlog::error(format, message);
}

void report_error(char const *format, int const value, bool const boolean_value,
                  std::string const &str) {
  spdlog::error(format, value, boolean_value, str);
}

void print_banner() {
  auto const header = R"sep("
·▄▄▄▄              ▄ •▄ ▄▄▄ .·▄▄▄▄  
██▪ ██ ▪     ▪     █▌▄▌▪▀▄.▀·██▪ ██ 
▐█· ▐█▌ ▄█▀▄  ▄█▀▄ ▐▀▀▄·▐▀▀▪▄▐█· ▐█▌
██. ██ ▐█▌.▐▌▐█▌.▐▌▐█.█▌▐█▄▄▌██. ██ 
▀▀▀▀▀•  ▀█▄▀▪ ▀█▄▀▪·▀  ▀ ▀▀▀ ▀▀▀▀▀• 

DNS and Target History Local Storage
Made with ❥ by codingo (https://twitter.com/codingo_)   
)sep";
  fprintf(stdout, "%s", header);
}
} // namespace dooked
