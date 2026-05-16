#pragma once

#include "dns/dns_resolver.hpp"
#include "utils/io_utils.hpp"
#include <regex>
#include <thread>

// maximum sockets to open regardless of the number of threads
// supported by the hardware

#define DOOKED_SUPPORTED_THREADS ((std::size_t)std::thread::hardware_concurrency())

namespace dooked {

enum class http_process_e { in_place, deferred };
using resolver_list_t = circular_queue_t<resolver_address_t>;

struct cli_args_t {
  std::string resolver{}; // defaults to 8.8.8.8
  std::string resolver_filename{};
  std::string output_filename{};
  std::string input_filename{};
  std::string last_seen_date{};
  std::string check_config_filename{};

  int file_type{};
  int post_http_request{};
  int thread_count{};
  int content_length{-1};
  int last_seen_days{-1};
  bool include_date{false};
  bool show_first_seen{false};
};

struct regex_check_t {
  std::string field{};
  std::regex pattern{};
  std::string pattern_text{};
  std::string alert{};
};

struct runtime_args_t {
  std::optional<resolver_list_t> resolvers{};
  opt_domain_list_t names{};
  std::optional<std::vector<json_data_t>> previous_data{};
  std::unique_ptr<std::ofstream> output_file{};
  std::string output_filename{};
  std::string run_timestamp{};
  std::string last_seen_date{};
  std::vector<regex_check_t> regex_checks{};
  http_process_e http_request_time_{};
  int thread_count{};
  int content_length{-1};
  int last_seen_days{-1};
  bool show_first_seen{false};
};

void run_program(cli_args_t const &cli_args);
void print_banner();
bool case_insensitive_compare(std::string const &, std::string const &);
} // namespace dooked
