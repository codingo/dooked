#pragma once

#include "dns/dns_resolver.hpp"
#include "utils/io_utils.hpp"
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

  int file_type{};
  int post_http_request{};
  int thread_count{};
  int content_length{-1};
  bool include_date{false};
};

struct runtime_args_t {
  std::optional<resolver_list_t> resolvers{};
  opt_domain_list_t names{};
  std::optional<std::vector<json_data_t>> previous_data{};
  std::unique_ptr<std::ofstream> output_file{};
  std::string output_filename{};
  http_process_e http_request_time_{};
  int thread_count{};
  int content_length{-1};
};

void run_program(cli_args_t const &cli_args);
void print_banner();
bool case_insensitive_compare(std::string const &, std::string const &);
} // namespace dooked
