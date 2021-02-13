#pragma once

#include "http/requests_handler.hpp"
#include "utils/containers.hpp"
#include "utils/probe_result.hpp"

namespace dooked {

class http_resolver_t {
  net::io_context &io_context_;
  domain_list_t &names_;
  map_container_t<probe_result_t> &result_map_;
  ssl::context *default_tls_context_{nullptr};
  std::optional<request_t> http_request_handler_{};
  std::optional<temporary_ssl_holder_t> tls_holder_{};
  std::string name_{};
  int http_redirects_count_{};
  int http_retries_count_{};
  // this should have been a boolean but it's an int to keep the alignment
  int is_default_tls_{1};

private:
  void perform_http_request();
  void switch_ssl_method(std::string const &);
  void send_next_request();
  void tcp_request_result(response_type_e, int, std::string const &);
  void send_http_request(std::string const &address);
  void send_https_request(std::string const &address);
  void on_resolve_error();

public:
  http_resolver_t(net::io_context &, ssl::context *, domain_list_t &,
                  map_container_t<probe_result_t> &);

  void start() { send_next_request(); }
};
} // namespace dooked
